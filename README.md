# rekor-falco

A Falco Plugin for Rekor Transparency Log Server

## Usage

You need to install [Falco](https://falco.org/docs/getting-started/installation/#installing) on your environment.

```shell
$ make all
```

Next, you need to spin up your Falco instance with plugin enabled, to do that run the following command below:

```shell
$ falco -r example-rule.yaml -c falco.yaml
```
> Do not forget to replace the email adress within the example-rule.yaml to verify it is working.
> Also make sure to change the library path in the falco.yaml to the directory your falco-rekor plugin 

Once Falco is up and running, you should sign something with cosign with experimental mode enabled:

```shell
$ COSIGN_EXPERIMENTAL=1 cosign sign devopps/alpine:3.15.0
```

Once the process finished, you should be able to see the alert triggerred by Falco.

> If you are running OSX environment you can use lima to use this plugin. Lima allows us to create linux environment on OSX. See [osx.md](docs/osx.md)

