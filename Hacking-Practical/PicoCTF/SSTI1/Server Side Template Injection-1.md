### Scenario

![[SSTI1-1.png]]
In this we have been given a input section which renders out whatever we give the input
![[SST1-2.png]]
Since we know it is vulnerable to basic SSTI lets try the payload:
```COPY
{{10*10}}
```
We get 100 which confirms that the input isnt sanitized
![[SSTI1-3.png]]
Now according to the following logic tree
![[SSTI1-3.webp]]
We can determine that the payload we used for checkking matches the second route which can be:
	1.Non-Vulnerable- does nothing.
	2.Not Known- Does give the output but we cant get to work with any known template engine
	3.Twig- A php based template engine that means php basic commands will work here
	4.Jinja2- A python based template engine which means basic python scripting commands will work here.
Since the payload return a value now we only need to check if it is twig or jinja2 lets try another payload:
```COPY
{{ self.__init__.__globals__.__builtins__ }}
```
We get alot of info here:
![[SSTI1-4.png]]
And if we scroll all the way to the bottom we can see python licensing area which confirms the engine to be jinja2:
![[SSTI1-5.png]]
Now we can use any python script break it down and use it to get a reverse shell,get info about system or even read system files and many more.
Lets use the following payload to get the uid of the user:
```COPY
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
We are ROOT!
![[SSTI1-6.png]]
You can edit `popen('id')` to any linux command for command injection like ls,cat and more!