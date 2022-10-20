all: serve

.PHONY: serve https build send
serve:
	env NODE_ENV=development yarn serve

HOST=stumpy.local
https:
	yarn run vue-cli-service serve --https --open --host $(HOST)

build:
	npm run build

TARGET=
send:
	rsync -e 'ssh -p 2215' dist/* $(TARGET) -Pavz

