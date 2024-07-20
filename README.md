# UAORT-4diac-plugin
4diac-ide Plugin to enable deployment on UAO Runtimes

### Install
For a step-by-step tutorial on the plugin instalation please refere to [Install.md](./INSTALL.md) document.

### Usage
To communicate with the UAO Runtime first add an `UAO_RT` device under the "System Configuration" view.

Edit the `MGR_ID` entry of the device to match the endpoint and port of the UAO Runtime.

Click on the Device block to select it and then on the `Properties` Tab. Under the `Instance` option select the "Profile" as `UAO`.

![Usage Video](./docs/BasicDeploy.gif)

After these steps the communication is configured and you can resume to the 61499 application build.

### Build from sources
Use `maven` tool to build the plugin with:
```shell
$ mvn clean
$ mvn install
```
After the command completes you will find the plugin installable zip file at [./package/target](./package/target) folder.
