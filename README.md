# JoanAudit 

[Overview](#Overview)

[Directory Structure](#Directory Structure)

[Capabilities of JoanAudit](#capabilities-of-joanaudit)

[Configuration](#Configuration)

[References](#references)

[Acknowledgements](#acknowledgements)

# Overview

JoanAudit is a security-slicing tool based on the [Joana](http://pp.ipd.kit.edu/projects/joana/) framework which can be downloaded from
[here](https://github.com/jgf/joana).

<img src="https://github.com/julianthome/joanaudit/blob/master/img/tool.png" alt="Overview" width="200px">

## Directory Structure

The directories of this repository and their meaning are as follows:

* bin/: the JoanAudit binary
* cfg/: a sample configuration file
* cstudies/: the web applications that we used in our evaluation

## Cababilities of JoanAudit

JoanAudit is a single executable *.jar*-File that can be executed right from a shell. 
For executing it, please set the environment variable *JAVA_HOME* first by typing the 
following command:

``` bash
export JAVA_HOME="<path>"
```

After that, one can execute JoanAudit by typing:

``` bash
java -jar JoanAudit.jar <options>
```

## Configuration

The configuration parts consists of several parts. The following XML file illustrates the different sections. 

``` xml
<configuration xmlns:xi="http://www.w3.org/2001/XInclude"
	xmlns="http://wwwen.uni.lu/snt" xmlns:xs="http://www.w3.org/2001/XMLSchema-instance"
	xs:schemaLocation="http://wwwen.uni.lu/snt config.xsd">
	<xi:include href="sources.xml" />
	<xi:include href="sinks.xml" />
	<xi:include href="declassifiers.xml" />
	<xi:include href="lattice.xml" />
	<xi:include href="exclusions.xml" />
	<xi:include href="entrypoints.xml" />
	<xi:include href="classes.xml"/>
</configuration>
```


