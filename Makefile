all: serve

.PHONY: serve https
serve:
	env NODE_ENV=development yarn serve

HOST=stumpy.local
https:
	yarn run vue-cli-service serve --https --open --host $(HOST)
