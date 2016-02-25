Terraform Security Group viewer
----
# Terraform plan の SG変更を何とかする。
対応しているのは SG新規作成および、変更のみ
SG自体の削除は対応しない。

# 使い方
標準入力に変えた
`./tfsgv.rb < [output_terraform_plan]`
or
`terraform plan | ./tfsgv.rb`
