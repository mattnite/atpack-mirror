#!/bin/sh

set -eu

cat <<EOF
job "atpack-mirror" {
  datacenters = ["dc1"]
  type = "service"
  constraint {
    attribute = "\${meta.node_id}"
    value     = "atpack-mirror"
  }

  group "app" {
    count = 1

    volume "atpack-mirror" {
      type = "host"
      read_only = false
      source = "atpack-mirror"
    }

    task "web" {
      driver = "docker"

      config {
        network_mode = "host"
        image = "${IMAGE}"
        ports = ["http", "https"]
        logging {
          type = "loki"
          config {
            loki-url = "${LOKI_URL}/loki/api/v1/push"
            loki-external-labels = "job=atpack-mirror,env=prod"
          }
        }
      }

      volume_mount {
        volume = "atpack-mirror"
        destination = "/var/lib/atpack-mirror"
        read_only = false
      }

      env {
        CERTS_PATH = "/var/lib/atpack-mirror/certs"
        CACHE_PATH = "/var/lib/atpack-mirror/cache"
        HOST = "0.0.0.0"
        PORT = "443"
        DOMAIN = "${DOMAIN}"
        LOG_LEVEL = "${LOG_LEVEL}"
        GIN_MODE = "release"
      }
    }

    network {
      port "http" {
        static = 80
        to = 80
      }
      port "https" {
        static = 443
        to = 443
      }
    }
  }
}
EOF
