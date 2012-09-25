test:
	@./node_modules/.bin/mocha -u bdd -R spec

.PHONY: test testintegration
