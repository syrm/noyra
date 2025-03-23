service "smallapp" {
  domains = ["smallapp.local"]
  image = "192.168.1.39:50000/smallapp:0.3"
  expose = "80/tcp"

  deploy {
    type = "http"
    replicas = 3
  }
}

