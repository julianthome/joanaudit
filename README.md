# JoanAudit 

[Overview](#overview)

[Directory Structure](#directory-structure)

[Capabilities of JoanAudit](#capabilities-of-joanaudit)

[Configuration](#configuration)

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

# Configuration


The configuration parts consists of several parts. The following XML file illustrates the different sections. In the
following, we are assuming 

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

As one can see, the main configuration file includes configurations for source, sink and declassfier signatures, a configuration
part for the lattice, exclusion rules, i.e. a set of Java packages or classes that can be dropped during the SDG construction. Moreover,
the configuration includes a set of entrypoints, i.e. the starting points for SDG construction. The file *classes.xml* contains categories of sources, sinks, and declassifiers. If sources, sinks and declassifiers are connected by a path but do not belong
to the same category, the are filtered out. The following subsections explains the different parts of the configuration in
more detail.

## Security Lattice

The security lattice is used for information flow analysis. More specifically, it is used to augment 
parts of the SDG with security label for the purpose of doing IFC on potentially sensitive paths (from sources through declassifiers to sinks). We are using IFC to filter out those paths that can be considered as secure based on the IFC analysis.

A lattice is a partial ordered set of security levels. The configuration file *lattice.xml* illustrates the configuration of a simple diamond lattice as depicted in the figure below. The root tag is *<lattice>*  contains
two subtags, namely *levels* that defines the different security levels that should be present in the lattice the
*<relations>* tag contains the relations between them. Each *<level>* tag contains the name of the security level to
be used (*id*) and a short description text (*desc*). The *<smeq>* (smaller or equals) tags refer to the 
*id's* that are being used in the *id* attributes of the *<level>* tags. The attribute *lhs* stands for left hand side (the left side of the smaller or equals operation) whereas *lhs* is the left hand side. The partial order relation based on the configuration flow is highlighted in the lattice figure. 

``` xml
<!-- lattice xml -->
<lattice xmlns="http://wwwen.uni.lu/snt">
	<levels>
		<level id="LH" desc="non-confidential and trusted"/>
		<level id="HH" desc="confidential and trusted"/>
		<level id="LL" desc="nonconfidential and untrusted"/>
		<level id="HL" desc="confidential and untrusted"/>
	</levels>
	<relations>
		<smeq lhs="LL" rhs="HL"/>
		<smeq lhs="HH" rhs="HL"/>
		<smeq lhs="LH" rhs="LL"/>
		<smeq lhs="LH" rhs="HH"/>
	</relations>
</lattice> 
```

<img src="https://github.com/julianthome/joanaudit/blob/master/img/lattice.png" alt="Lattice" width="200px" align="middle">

## Sources, Sinks, Declassifiers

``` xml
<!-- sources .xml -->
<nodeset id="sources" xmlns="http://wwwen.uni.lu/snt">
	<category name="parameter tampering" abbreviation="src_pt">
		<node
				name="javax.servlet.ServletRequest.getParameter(Ljava/lang/String;)Ljava/lang/String;"
				parlabels="return(LL)"/>
	</category>
</nodeset>
```

The code listing above shows a sample configuration file that contains the bytecode signature
for a single source. The top element for all configuration files (for sinks, sources and declassifiers) is 
the *<nodeset>* tag. This tag can contain multiple *<category>* tags. Sources, sinks and declassifiers
are categorized which has to advantages: 

- We can just consider sources/sinks and declassifiers that belong to the same class. Thus, we
can filter out those paths where this is not true.
- We can create profiles for applications. If a developer has some knowledge about the application's
internals (which is usually the case), he can just consider consider those classes of sources, sinks
and declassifiers of his interest. 

The category attribute *name* and *abbreviation* can be freely defined. However, it is important to note that
*abbreviation* is used from JoanAudit to match given signatures with each other. The *<category>* tag can
have multiple *<node>* child tags that contain the java bytecode signature (*name*) and the label that
is assigned to a specific part of the same signature (*parlabel*). The *parlabel* attribute should match the following production rule: *(return|all|[0-9])(security-level)* and have the following meaning:

* return: Return node of the function is labeled.
* all: The whole function entry is labeled.
* [0-9]: Actual parameter with the given number is labeled (first actual parameter has index 0).
* security-level : The security label that is being used for the selected part. The configuration of this
  part is dependent on the lattice configuration where security levels can be freely defined in the
  *id* attribute o the *<level>* tag. In our diamond lattice example, security-level could be one of LL, HH, LH or HL.

In the example above the return value of *getParameter()* is supposed to be labeled with the *LL*.

The configuration for sinks listed below looks exactly the same as compared to the
configuration of sources, the only difference is the value of the *id*
which is *sinks* instead of *sources*. In the example below, we label the whole call entry
of *XPath.evaluate()* with the security label HH.

``` xml
<!-- sinks.xml -->
<nodeset id="sinks" xmlns="http://wwwen.uni.lu/snt">
	<node name="javax.xml.xpath.XPath.evaluate(Ljava/lang/String,Ljava/lang/Object;)Ljava/lang/String;"
	parlabels="all(HH)"/>
</category>
```

Besides sources and sinks, there is also the declassifier configuration listed below.

``` xml
<!-- declassifiers.xml -->
<nodeset id="declassifiers" xmlns="http://wwwen.uni.lu/snt">
<category name="xpath injection" abbreviation="dcl_xi">
	<node name="org.owasp.esapi.Encoder.encodeForXPath(Ljava/lang/String;)Ljava/lang/String;"
	parlabels="0(LL>LH)"/>
</category>
```
By and large, the declassifier configuration is the same as compared to sources and sinks with two exceptions: The *id* tag must have the value *declassifiers*, and the structure of the attribute *parlabels* has to match the production rule *(return|all|[0-9]\*)(security-level0 > secuirty-level1)* whereas *securitylevel0* is the required and *security-level1* is the provided security level. The required security level imposes the restriction on arriving information to have a security level smaller or equals than *securityLevel0* whereas *securityLevel1* is the 
security-level to which the arriving information should be declassified to. Declassification only makes sense if 
*security-level1* is smaller or equals than *security-level0*. In our example above, we declassify the information
that passes through the first parameter of *encodeForXPath()* from *LL* (non-confidential and untrusted) to
*LH* (confidential and untrusted). In other words, we are lowering the cautiousness of data that passes through the
*encodeForXPath()* because it prevents malicious users of launching XPath attacks. *LH* data can be used more freely than *LL* data.

## Exclusions

Exclusion rules are useful for improving scalability by reducing the SDG construction time. The following code snippet
illustrates a sample configuration for excluding three packages from the SDG build process. You can also
exclude single classes. In the example below, two packages and one class are filtered out.

``` xml
<exclusions xmlns="http://wwwen.uni.lu/snt">
	<exclusion pattern="java/awt/.*"/>
	<exclusion pattern="javax/swing/.*"/>
	<exclusion pattern="org/eclipse/jetty/util/StringMap.*"/>
</exclusions>
```

## Entrypoints

Entrypoints are starting points for the SDG generation. JoanAudit analyzes the bytecode and searches for possible entrypoints. The following code snippet configures 4 possible entrypoints, namely *doPost()*, *doGet()*, *service()*
and main, whereas the former 3 share the same prefix given in the *name* attribute of the *<entrypoint>* tag. JoanAudit searches for entrypoint with matching signatures and for implementations of the same function for classes
that inherit or implement from other classes, abstract classes and/or interfaces.

``` xml
<entrypoints  xmlns="http://wwwen.uni.lu/snt">
	<entrypoint class="javax.servlet.http.HttpServlet">
		<function name="doPost(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V"/>
		<function name="doGet(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V"/>
		<function name="service(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V"/>
	</entrypoint>
	<entrypoint>
		<function name="main([Ljava/lang/String;)V"/>
	</entrypoint>
</entrypoints>
```

## Classes/Categories

The categorization of sources, sinks and declassifiers helps to reduce the amount of potentially vulnerable paths that might be reported by JoanAudit and, hence, it reduces the manual effort for security auditors. 

The first reason for using categories is that some declassifiers and sinks are not related 
while others are. For example, the sanitization function *encodeForXPath()* sanitizes strings that can be used
safely as parameter of *XPath.evaluate()*. But a flow of a string that contains the result of *encodeForXpath()* 
to an SQL sink like *executeQuery()* cannot be considered as safe.

The second reason for using categories is to allow security auditors to profile the application under test. If you have a rich set of sources, sinks and declassifiers, auditors do not want to create a new configuration for each
application. They can use categories instead, to focus their auditing task just on particular sources, sinks and
can leave out all functions that are known to be secure. The configuration example below means that just 
sources that belong to the category *src_pt* (as configured in *sources.xml*), declassifiers that belong
to the category *dcl_xi* (as configured in *declassifiers.xml*), and sinks that belong to the category *snk_xi*
should be matched.

``` xml
<class desc="xpath injection">
	<elem name="src_pt"/>
	<elem name="dcl_xi"/>
	<elem name="snk_xi"/>
</class>
```


# Usage

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

For looking at the different command line options provided by JoanAudit, please type the following command:

``` bash
java -jar JoanAudit.jar -h
```

The following table explains the meaning of the different options that can be configured:


| biofuzz-tk        | meaning | 
| ------------- |:-------------:| 
|-arch,--archivepath <arch>   |               Path to the jar file to test 
                                             for security vulnerabilites -
                                             note that this does not work
                                             for ear/war (extract them
                                             first and use the dir option)|
| -cfg,--config <cfg>        |                 Path to the JoanAudit
                                             configuration file in XML
                                             format. The basename has to
                                             be config.xml. You can work
                                             with xincludes.|
| -chopout,--chop-out-file <chopoutputfile> |  serialize the chop to a file |
| -cp,--classpath <cp>  |                      Classpath - multiple entries |
                                             should be separated by ':'
| -dir,--directorypath <dir>   |               path to the directory |
                                             containing the java sources
| -ept,--entrypoint <entrypoint>  |            The entrypoint to start the
                                             analysis |
| -h                           |               print this message |
| -in,--sdg-in-file <inputfile>  |             read the SDG file |
| -jbd,--joanabasedir <jbd>     |              Joana Basedir - needed to
                                             load Java stubs. |
| -lept,--list_entrypoints    |                List all possible entrypoints
                                             (config.xml is used for
                                             filtering) |
| -sdgout,--sdg-out-file <outputfile>  |       serialize the SDG to a file
| -src,--check_sources      |                  Check all java source files |



# References

* [Joana Website](http://pp.ipd.kit.edu/projects/joana/)
* [Joana Source Code](https://github.com/jgf/joana)
