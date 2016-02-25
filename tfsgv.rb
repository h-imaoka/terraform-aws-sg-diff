#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

require 'pp'

begin
  sg_name = ""
  rule_id = ""
  all_sg = {}
  sg_info = {}


  STDIN.read.split("\n").each do |line|
    pp line
    if m = line.match(/^[\+~]\saws_security_group\.(\S+)/)
      sg_name = m[1]
      sg_info = {}
    end

    if line == "" and sg_name != ""
      all_sg[sg_name] = sg_info
      sg_name = ""
    end

    if sg_name != "" and
      m = line.match(/\s+([^.]+\.[^.]+\.[^:]+):\s+"([^"]*)"\s+=>\s+"([^"]*)"/) then
      arr = m[1].split('.')

      if m[2] == m[3]
        next
      end

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
        p sg[pr['new']]['cidr_blocks'] - sg[pr['old']]['cidr_blocks']
        puts 'revoke'
        p sg[pr['old']]['cidr_blocks'] - sg[pr['new']]['cidr_blocks']
      elsif pr.key? 'old'
        puts 'revoke'
        p sg[pr['old']]['cidr_blocks']
      else
        puts 'authorize'
        p sg[pr['new']]['cidr_blocks']
      end
    end

  end

rescue SystemCallError => e
  puts %Q(class=[#{e.class}] message=[#{e.message}])
rescue IOError => e
  puts %Q(class=[#{e.class}] message=[#{e.message}])
end
