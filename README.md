<h1 align="center">Agent Semgrep</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Semgrep is a fast, open-source, static analysis engine for finding bugs, detecting vulnerabilities in third-party dependencies, and enforcing code standards. Semgrep analyzes code locally on your computer or in your build environment: code is never uploaded._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_semgrep/blob/main/images/logo.png" alt="agent-semgrep" />
</p>

This repository is an implementation of [Ostorlab Agent](https://pypi.org/project/ostorlab/) for [Semgrep](https://github.com/returntocorp/semgrep).

## Getting Started
To perform your first scan, simply run the following command.
```shell
ostorlab scan run --install --agent agent/ostorlab/semgrep file code.java
```

This command will download and install `agent/ostorlab/semgrep` and analyze the file `code.java`.
For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)


## Usage

Agent Semgrep can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from ostorlab agent store

 ```shell
 ostorlab agent install agent/ostorlab/semgrep
 ```

You can then run the agent with the following command:
```shell
ostorlab scan run --install --agent agent/ostorlab/semgrep file code.java
```


### Build directly from the repository

 1. To build the semgrep agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_semgrep.git && cd agent_semgrep
```

 3. Build the agent image using ostorlab cli.

 ```shell
 ostortlab agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
	  ```shell
	  ostorlab scan run --agent agent//semgrep file code.java
	  ```
	 * If you specified an organization when building the image:
	  ```shell
	  ostorlab scan run --agent agent/[ORGANIZATION]/semgrep file code.java
	  ```


## License
[Apache-2](./LICENSE)

