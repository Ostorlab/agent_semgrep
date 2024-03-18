
<h1 align="center">Agent Semgrep</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Semgrep is a fast, open-source, static analysis engine for finding bugs, detecting vulnerabilities in third-party dependencies, and enforcing code standards. Semgrep analyzes code locally on your computer or in your build environment: code is never uploaded._

---


This repository is an implementation of [OXO Agent](https://pypi.org/project/ostorlab/) for [Semgrep](https://github.com/returntocorp/semgrep).

## Getting Started
To perform your first analysis, simply run the following command.
```shell
oxo scan run --install --agent agent/ostorlab/semgrep file code.c
```

This command will download and install `agent/ostorlab/semgrep` and analyze the source file `code.c`.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent Semgrep can be installed directly from the oxo agent store or built from this repository.

 ### Install directly from oxo agent store

 ```shell
 oxo agent install agent/ostorlab/semgrep
 ```

You can then run the agent with the following command:
`oxo scan run --install --agent agent/ostorlab/semgrep file code.c`


### Build directly from the repository

 1. To build the semgrep agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_semgrep.git && cd agent_semgrep
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
	  ```shell
	  oxo scan run --agent agent//semgrep file code.c
	  ```
	 * If you specified an organization when building the image:
	  ```shell
	  oxo scan run --agent agent/[ORGANIZATION]/semgrep file code.c
	  ```


## License
[Apache](./LICENSE)