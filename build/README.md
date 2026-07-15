# Build instructions

```
export HALON_REPO_USER=exampleuser
export HALON_REPO_PASS=examplepass
docker compose -p halon-extras-pgp --profile all up --build
docker compose -p halon-extras-pgp down --rmi local
```