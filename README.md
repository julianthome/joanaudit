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

<img src="https://github.com/julianthome/joanaudit/blob/master/img/tool.png" alt="Overview" width="400px" align="middle">

The general overview is depicted in the figure above. The user configures a lattice (a partial order relation) and provides 
a list of source, sink and declassifier bytecode signatures with their respective security levels. 
Sources are functions that return data that is manipulable by a user (e.g. ``getParameter()`` or ``System.getProperty()``); 
sinks are usually sensitive functions where user provided data might flow to and is processed (e.g. ``executeQuery()``), 
and declassifiers are function that escape user-provided, potentially malicious, input. 
By means of Joana, JoanAudit generates an System Dependence Graph (SDG) from the Java bytecode and automatically 
annotates the given source code based on the pre-defined list of sources, sinks and declassifiers. 
After that, JoanAudit creates a list of security slices between sources and sinks, by filtering-out 
those paths that are irrelevant or that do not contain an illegal flow between sources and sinks. The output
of JoanAudit is a report that lists potentially vulnerable paths of the program being analyzed. JoanAudit is a tool
that helps security auditors to perform their security auditing tasks more efficiently by pinpointing potentially 
vulnerable paths of a given program.


# Directory Structure

The directories of this repository and their meaning are as follows:

* bin/: the JoanAudit binary
* cfg/: a sample configuration file
* cstudies/: the web applications that we used in our evaluation

# Capabilities of JoanAudit

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

# Configuration

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

# References

* [Joana Website](http://pp.ipd.kit.edu/projects/joana/)
* [Joana Source Code](https://github.com/jgf/joana)

