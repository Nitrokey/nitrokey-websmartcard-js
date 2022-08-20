all: serve

.PHONY: serve https
serve:
	yarn serve

HOST=stumpy.local
https:
	yarn run vue-cli-service serve --https --open --host $(HOST)
