#!/bin/sh

sudo docker-compose -f csc2024-project1-docker-compose.yml up -d

docker exec -it server bash