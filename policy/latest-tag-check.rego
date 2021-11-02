package main

#イメージタグにlatestがある場合
deny[msg] {
  input.kind == "Deployment"
  image := input.spec.template.spec.containers[_].image
  endswith(image, "latest")
  msg := sprintf("latest tag: %s", [ image ])
}

#イメージタグに指定がない場合
deny[msg] {
  input.kind == "Deployment"
  image := input.spec.template.spec.containers[_].image
  not contains(image, ":")
  msg := sprintf("latest tag: %s", [ image ])
}

