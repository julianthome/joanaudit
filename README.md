# JoanAudit

[Overview](#overview)

[Directory Structure](#directory-structure)

[Usage](#usage)

[Installation and Configuration](#installation_and_configuration)

[Case Studies](#case-studies)

[Notes](#notes)

[References](#references)


:warning: We are currently working on a new version of JoanAudit which will be uploaded soon. We improved the scalability, automated fixing, and the report generation.

# Overview

JoanAudit is a program slicing tool for automatic extraction of security slices from Java Web programs. Security slices are concise and minimal pieces of code that are essential for auditing XML, XPath, and SQL injection--common and serious security issues for Web applications and Web services. It is based on the [Joana](http://pp.ipd.kit.edu/projects/joana/) framework which may be downloaded from [here](https://github.com/jgf/joana).

![](https://www.dropbox.com/s/7yvzjmosomjg9ln/tool.png?dl=1)

The general overview is depicted in the figure above. The user configures a lattice (a partial order relation)
and provides a list of source, sink and declassifier bytecode signatures with their respective security levels.
Sources are functions that return data that is manipulable by a user (e.g. ``getParameter()`` or
``System.getProperty()``); sinks are usually sensitive functions where user provided data might
flow to and is processed (e.g. ``executeQuery()``);
and declassifiers are functions that escape user-provided, potentially malicious input.
By means of Joana, JoanAudit generates a System Dependence Graph (SDG) from the Java bytecode and automatically
annotates the given source code based on the pre-defined list of sources, sinks and declassifiers.
Afterwards, JoanAudit creates a list of security slices between sources and sinks, by filtering-out
those paths that are irrelevant or that do not contain an illegal flow between sources and sinks. The output
of JoanAudit is a report that lists potentially vulnerable paths of the program being analyzed. JoanAudit is a tool
that helps security auditors to perform their security auditing tasks more efficiently by pinpointing potentially
vulnerable paths of a given program.


# Directory Structure

The directories of this repository and their meaning are as follows:

* cfg/: A sample configuration file. If you want to adjust JoanAudit to your needs, please add your own
signatures. You can follow the examples present in the configuration files (*config.xml* is the
main configuration file).
* modules/ : The Joana submodule

# Installation and Configuration

Thie JoanAudit binary can be obtained from [here](https://www.dropbox.com/s/3dtkjzwu4ffa7cv/joanaudit.zip?dl=1)
The configuration parts consists of several parts. The following XML file illustrates the different sections.

``` xml
<!-- config.xml -->
<configuration xmlns:xi="http://www.w3.org/2001/XInclude" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="config.xsd">
  <xi:include href="sources.xml" />
  <xi:include href="sinks.xml" />
  <xi:include href="declassifiers.xml" />
  <xi:include href="lattice.xml" />
  <xi:include href="exclusions.xml" />
  <xi:include href="irrelevantprocs.xml" />
  <xi:include href="entrypoints.xml" />
  <xi:include href="classes.xml"/>
  <xi:include href="autofix.xml"/>
</configuration>
```

The main configuration file includes configurations for source, sink and declassifier signatures, a configuration
part for the lattice, exclusion rules, i.e. a set of Java packages or classes that can be dropped during the SDG construction as well as
irrelevant functions that are not traversed when performing the slicing. Moreover,
the configuration includes a set of entrypoints, i.e. the starting points for SDG construction. The file *classes.xml* contains categories of sources, sinks, and declassifiers. If sources, sinks and declassifiers are connected by a path but do not belong
to the same category, they are filtered out. The file *autofix.xml* contains mappings from sinks to declassifier and context patterns that a string that flows to a sink has to match in order to identify an appropriate declassifier to fix the vulnerability. The following subsections explain the different parts of the configuration in detail.

## Security Lattice

The security lattice is used for information flow analysis. More specifically, it is used to augment
parts of the SDG with security label for the purpose of performing IFC on potentially sensitive paths (from sources through declassifiers to sinks). We are using IFC to filter out those paths that can be considered as secure based on the IFC analysis.

A lattice is a partial ordered set of security levels. The configuration file *lattice.xml* illustrates the configuration of a [diamond lattice](http://www.cs.cornell.edu/andru/papers/robdecl-jcs.pdf) as depicted in the figure below. The root tag *lattice* contains
*levels* subtags that define the different security levels of the lattice, whereas the
*relation>* tag contains the relations between them. Each *level* tag contains the name of the security level to
be used (*id*) and a short description text (*desc*). The *smeq* (smaller or equals) tags refer to the
*id's* that are being used in the *id* attributes of the *level* tags. The attribute *lhs* stands for left hand side (the left side of the smaller or equals operation) whereas *lhs* is the left hand side. The partial order relation based on the configuration flow is highlighted in the lattice figure.

``` xml
<!-- lattice xml -->
<lattice>
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

![](https://www.dropbox.com/s/swqeiolv8sryd5e/lattice.png?dl=1)

## Sources, Sinks, Declassifiers

``` xml
<!-- sources .xml -->
<nodeset id="sources">
	<category name="parameter tampering" abbreviation="src_pt">
		<node name="javax.servlet.ServletRequest.getParameter(Ljava/lang/String;)Ljava/lang/String;" parlabels="return(LL)"/>
		<!-- ... -->
	</category>
<!-- ... -->
</nodeset>
```

The code listing above shows a sample configuration file that contains the bytecode signature
for a single source. The top element for all configuration files (for sinks, sources and declassifiers) is
the *nodeset* tag. This tag may contain multiple *category* tags. Sources, sinks and declassifiers
are categorized which has two advantages:

- We can just consider sources/sinks and declassifiers that belong to the same class. Thus, we
can filter out those paths where this is not true.
- We can create profiles for applications. If a developer has some knowledge about the internals of the application (which is usually the case), he may just consider consider those classes of sources, sinks
and declassifiers that are of interest to him.

The category attribute *name* and *abbreviation* can be freely defined. However, it is important to note that
*abbreviation* is used from JoanAudit to match given signatures with each other. The *category* tag can
have multiple *node* child tags that contain the java bytecode signature (*name*) and the label that
is assigned to a specific part of the same signature (*parlabel*). The *parlabel* attribute should match the following production rule: *(return|all|[0-9]+)(security-level)* and have the following meaning:

* return: Return node of the function is labeled.
* all: The whole function entry is labeled.
* [0-9]: Actual parameter with the given number is labeled (first actual parameter has index 1).
* security-level : The security label that is being used for the selected part. The configuration of this
  part is dependent on the lattice configuration where security levels can be freely defined in the
  *id* attribute of the *level* tag. In our diamond lattice example, security-level could be one of LL, HH, LH or HL.

In the example above, the return value of *getParameter()* is supposed to be labeled with the *LL*.

The configuration for sinks listed below looks exactly the same as compared to the
configuration of sources, and the only difference is the value of the *id*
which is *sinks* instead of *sources*. In the example below, we label the whole call entry
of *XPath.evaluate()* with the security label HH.

``` xml
<!-- sinks.xml -->
<nodeset id="sinks">
	<category abbreviation="snk_xi"/>
		<node name="javax.xml.xpath.XPath.evaluate(Ljava/lang/String,Ljava/lang/Object;)Ljava/lang/String;" parlabels="1(HH)"/>
		<!-- ... -->
	</category>
<!-- ... -->
</nodeset>
```

Besides sources and sinks, there is also the declassifier configuration listed below.

``` xml
<!-- declassifiers.xml -->
<nodeset id="declassifiers">
	<category name="xpath injection" abbreviation="dcl_xi">
		<node name="org.owasp.esapi.Encoder.encodeForXPath(Ljava/lang/String;)Ljava/lang/String;" parlabels="1(LL>LH)"/>
	<!-- ... -->
	</category>
<!-- ... -->
</nodeset>
```
By and large, the declassifier configuration is the same as compared to sources and sinks with two exceptions: the *id* tag must have the value *declassifiers*, and the structure of the attribute *parlabels* has to match the production rule *(return|all|[0-9]+)(security-level0 > secuirty-level1)* whereas *securitylevel0* is the required and *security-level1* is the provided security level. The required security level imposes the restriction on arriving information to have a security level smaller then or equal to than *securityLevel0* whereas *securityLevel1* is the
security-level to which the arriving information should be declassified to. Declassification only makes sense if
*security-level1* is smaller or equals than *security-level0*. In our example above, we declassify the information
that passes through the first parameter of *encodeForXPath()* from *LL* (non-confidential and untrusted) to
*LH* (confidential and untrusted). In other words, we are lowering the cautiousness of data that passes through the
*encodeForXPath()* since it prevents malicious users from launching XPath attacks. *LH* data can be used more freely than *LL* data.

## Exclusions and Irrelevant functions

Exclusion rules are useful for improving scalability by reducing the SDG construction time. The following code snippet
illustrates a sample configuration for excluding three packages from the SDG build process. You can also
exclude single classes. In the example below, two packages and one class are filtered out.

``` xml
<exclusions xmlns="http://wwwen.uni.lu/snt">
	<exclusion pattern="java/awt/.*"/>
	<exclusion pattern="javax/swing/.*"/>
	<exclusion pattern="org/eclipse/jetty/util/StringMap.*"/>
<!-- ... -->
</exclusions>
```

The configuration file for irrelevant functions is structured similarly. However, irrelevant procedures are kept in the SDG and are ignored in the slicing phase.

## Entrypoints

Entrypoints are starting points for the SDG generation. JoanAudit analyzes the bytecode and searches for possible entrypoints. The following code snippet configures 4 possible entrypoints, namely *doPost()*, *doGet()*, *service()*
and main, whereas the former 3 share the same prefix given in the *name* attribute of the *entrypoint* tag. JoanAudit searches for entrypoint with matching signatures and for implementations of the same function for classes
that inherit or implement from other classes, abstract classes and/or interfaces.

``` xml
<!-- entrypoints.xml -->
<entrypoints>
	<entrypoint class="javax.servlet.http.HttpServlet">
		<function name="doPost(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V"/>
		<function name="doGet(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V"/>
		<function name="service(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V"/>
		<!-- ... -->
	</entrypoint>
	<entrypoint>
		<function name="main([Ljava/lang/String;)V"/>
	</entrypoint>
<!-- ... -->
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
<!-- classes.xml -->
<classes>
	<class desc="xpath injection">
		<elem name="src_pt"/>
		<elem name="dcl_xi"/>
		<elem name="snk_xi"/>
		<!-- ... -->
	</class>
<!-- ... -->
</classes>
```

## Autofix (experimental)

JoanAudit tries to infer the string that reaches a sink by using a simple form of symbolic execution that can deal with simple string operations. Moreover, JoanAudit computes the context of the input variables. For an XPath sink that is labelled with *snk_xi* in sinks.xml, we might compute a result string like ```/users/user[@nick='v1' and @password='v2']``` where *v1* and *v2* are symbolic input variables. For each symbolic variable, JoanAudit applies the patterns that are specified in the *vulnerability* tag (for v1 on ```/users/user[@nick='``` and for v2 on ```/users/user[@nick='v1' and @password='```). If there is a match, the declassifier that is configured within the *dcl* attribute can be applied (in the example below *dcl_xi*, which refers to the ESAPI sanitisation function configured in *declassifiers.xml*, is used).

``` xml
<!-- autofix.xml -->
<autofix>
	<vulnerability sink="snk_xi">
		<context pattern=".*" dcl="dcl_xi"/>
		<!-- ... -->
	</vulnerability>
<!-- ... -->
</autofix>
```

# Usage

JoanAudit is a single executable *.jar*-File that can be executed right from a shell.
To execute it, please set the environment variable *JAVA_HOME* first by typing the
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


| biofuzz-tk (short/ long option)        | meaning |
| :---------------------------------------------------- | :--------------------------|
|-arch,--archivepath <arch>   | Path to the jar file to test for security vulnerabilites - note that this does not work for ear/war (extract them first and use the dir option) |
| -cfg,--config <cfg>        |  Path to the JoanAudit configuration file in XML format. The basename has to be config.xml. You can work with xincludes.|
| -cp,--classpath <cp>  |                      Classpath - multiple entries should be separated by ':' |
| -dir,--directorypath <dir>   |               Path to the directory containing the java sources |
| -ept,--entrypoint <entrypoint>  |            The entrypoint to start the analysis |
| -fix,--autofix 			|   Try to fix vulnerability (autofix.xml is used for filtering)|
| -h                           |               Print this message |
| -in,--sdg-in-file <inputfile>  |             Read the SDG file |
| -jbd,--joanabasedir <jbd>     |              Joana Basedir - needed to load Java stubs. |
| -lept,--list_entrypoints    |                List all possible entrypoints |
| -sdgout,--sdg-out-file <outputfile>  |       Serialize the SDG to a file |
| -pch,--print-class-hierarchy  |              Dump the class hierarchy|
|-nvul,--num-of-vuln <nvul> |  number of vulnerabilities considered per source-sink pair |
|-dcl,--with_declassification | use declassfication filter|

Joana provides stubs for Java. Stubs are useful for reducing the SDG construction time. For getting the stubs please launch the following commands in the git repository.

``` bash
git submodule init
git submodule update
```

The Joana sources are available in the *./modules/joana* directory then. Let us assume, one would like to analyze the JAR archive *foo.jar*, the following steps can be performed:

## Listing possible entrypoints

Every function can be defined as entrypoint. Per default, JoanAudit searches for entrypoints that are configured in the *entrypoints.xml* section of the configuration file *config.xml*.

``` bash
java -jar JoanAudit.jar -jbd ../modules/joana/ -arch foo.jar -lept -cfg config.xml -cp "lib.jar"
```

The *jbd* option points the the location of the joana directory. The option *arch* is devoted to the JAR archive of the program to be analyzed. The *lept* options is used for printing out all entrypoints that are present in the application. The generic entrypoints that are present in the configuration file are used as filters. The *cp*
option is used for defining libraries that have to be or that should be included for constructing the SDG. In case
of multiple libraries, one can separate them using *':'*. A possible output from JoanAudit might look as follows:

``` bash
ept: simple.Simple.doGet(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V
ept: simple.Simple.doPost(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V
```


## Printing potentially vulnerable paths

With the entrypoints that were returned after launching the command above, we can analyze the program
with the following command:

``` bash
java -jar JoanAudit.jar -jbd ../modules/joana/ -arch foo.jar -ept "simple.Simple.doPost(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V" -cfg config.xml -cp "lib.jar" -dcl -nvul 1
```

JoanAudit might produce the following output:

``` bash
For sink xpath injection (snk_xi)(145):
PATH BEGIN------------------------------------------
* Control Flow:[org/owasp/webgoat/lessons/XPATHInjection.java] 131->132->138->139->140->141->142->143->144->145
* Data Flow:([org/owasp/webgoat/lessons/XPATHInjection.java] 143->145)(141->145)(144->143)(143->144)(131->143)(139->142)(140->141)(138->139)(131->132)
* Control Dependencies:([org/owasp/webgoat/lessons/XPATHInjection.java] 143->145)(144->143)(143->144)(142->143)(141->142)(140->141)(139->140)(138->139)(132->138)
* Conditions :[org/owasp/webgoat/lessons/XPATHInjection.java] 132
* Nodes :73
* Edges :36
PATH END--------------------------------------------
```

JoanAudit reports the complete Path, Condition, Control Dependencies (CtrlDeps) and Calls in sequences of line numbers. If there is a scope change (calls that lead the execution to another class), the target class is highlighted in brackets *[]*.

# Case Studies

In our experiments, we evaluated JoanAudit on the following test subjects:

* [PubSubHubbub 0.3](https://code.google.com/p/pubsubhubbub/)
* [WebGoat 5.2](https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project)
* [Apache Roller 5.1.1](http://roller.apache.org/)
* [Pebble 2.6.4](http://pebble.sourceforge.net/)
* [Regain 2.1.0](http://regain.sourceforge.net/download.php?lang=de)

# Notes

JoanAudit is a "proof-of-concept" research prototype. If you find bugs or if you have suggestions how to improve it, please send an e-mail to julian.thome@uni.lu.

# References

* [Joana Website](http://pp.ipd.kit.edu/projects/joana/)
* [Joana Source Code](https://github.com/jgf/joana)
* [Declassification/Lattice](https://www.cs.cornell.edu/andru/papers/csfw04.pdf)
