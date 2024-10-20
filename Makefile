dev:
	goreload main.go

compose-up:
	docker-compose up -d

compose-down:
	docker-compose down