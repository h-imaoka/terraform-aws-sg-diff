#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

require 'pp'

class String
  def hex2bin
    s = self
    raise "Not a valid hex string" unless(s =~ /^[\da-fA-F]+$/)
    s = '0' + s if((s.length & 1) != 0)
    s.scan(/../).map{ |b| b.to_i(16) }.pack('C*')
  end

  def bin2hex
    self.unpack('C*').map{ |b| "%02X" % b }.join('')
  end
end

begin
  sg_name = ""
  rule_id = ""
  all_sg = {}
  sg_info = {}

  File.open(ARGV[0]) do |file|
    file.each_line do |line|
      if m = line.match(/^[\+~]\saws_security_group\.(\S+)/)
        sg_name = m[1]
        sg_info = {}
      end

      if line == "\n" and sg_name != ""
        all_sg[sg_name] = sg_info
        sg_name = ""
      end

      if sg_name != "" and
        m = line.match(/\s+([^.]+\.[^.]+\.[^:]+):\s+"([^"]*)"\s+=>\s+"([^"]*)"/) then
        arr = m[1].split('.')
        if m[1].end_with? "cidr_blocks.#"
          rule_id = arr[0]+'_'+arr[1]
          sg_info[rule_id] = {}
          sg_info[rule_id]['dir'] =  arr[0]
          sg_info[rule_id]['cidr_blocks'] = []
          sg_info[rule_id]['new'] = ( (m[2] == "0" or m[2] == "") ? 'new' : 'old')
        else
          if arr[2] == 'cidr_blocks'
            sg_info[rule_id]['cidr_blocks'] << (m[2] != "" ? m[2] : m[3])
          elsif arr[2] == 'security_groups'
            # todo: sg diff
          else
            sg_info[rule_id][arr[2]] = (m[2] != "" ? m[2] : m[3])
          end
        end

      end
    end
  end

  all_sg.each do |k, sg|
    puts k
    pair = {}
    sg.each do |l, rule|
      pk = rule['dir'] + '_' + rule['protocol'] + '_' + rule['from_port'] + '_' + rule['to_port']
      pair[pk] = {} if not pair[pk]
      pair[pk][rule['new']] = l
    end

    pair.each do |m, pr|
      puts m
      if pr.key? 'old' and pr.key? 'new'
        puts 'authorize'
        p sg[pr['old']]['cidr_blocks'] - sg[pr['new']]['cidr_blocks']
        puts 'revoke'
        p sg[pr['new']]['cidr_blocks'] - sg[pr['old']]['cidr_blocks']
      elsif pr.key? 'old'
        puts 'revoke'
        p sg[pr['old']]['cidr_blocks']
      else
        puts 'authorize'
        p sg[pr['new']]['cidr_blocks']
      end
    end

  end

# 例外は小さい単位で捕捉する
rescue SystemCallError => e
  puts %Q(class=[#{e.class}] message=[#{e.message}])
rescue IOError => e
  puts %Q(class=[#{e.class}] message=[#{e.message}])
end
