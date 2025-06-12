### Scenario

![[SSTI1-1.png]]
In this we have been given a input section which renders out whatever we give the input
![[SST1-2.png]]
Since we know it is vulnerable to basic SSTI lets try the payload:
```COPY
{{10*10)}}
```
