# Pehchaan API

`
docker-compose up -d
`

## Creating admin or first user

`
docker exec pehchaan-api_api_1 python manage.py create_admin <nic> <name> <email> <phone> <password>
`
