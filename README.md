# ea-smm
Enterprise Architecture Security Meta-Model Extended by Maturity Models.

This is a research in progress.

This meta-model extends [this](https://ieeexplore.ieee.org/document/6378394/) paper by C2M2 maturity models

# injectMaturity Method
```C
1.	context: AccessCategory   
2.	def injectMaturity (cysemolProbability:Real): Real  
3.	let averageMaturity:Real=MaturityArea.allInstances()->reject(m:MaturityArea|m.accessCategory->excludes(self))->iterate(m:MaturityArea;sum:Real=0|sum+m.maturityLevel)/MaturityArea.allInstances()->reject(m:MaturityArea|m.accessCategory->excludes(self))->size() in
4.	let maturityImpact:Real = 0.05 in
5.	cysemolProbability-(cysemolProbability*maturityImpact*(averageMaturity))

```

# FindPublicPatchableVulnerability.isAccessible 
```C
1.	let os_next : Real = bernoulli(self.vulnerabilityCategory->injectMaturity(0.980476376))  
2.	let os : Real = bernoulli(self.vulnerabilityCategory->injectMaturity(gamma(0.014593,3630.152,Attacker.Time))) 
3.	let application_next : Real = bernoulli(self.vulnerabilityCategory->injectMaturity(0.789867155)   
4.	let application : Real = bernoulli(self.vulnerabilityCategory->injectMaturity(lognormal(-68.4235,46.16324,Attacker.Time)) 
5.	  
6.	if visited->intersection(self.getProductInformation)->notEmpty() and defenseAvailable(self.softwareProduct.hasBeenScrutinized->asSet()) then  
7.	    if self.softwareProduct.operatingSystem->notEmpty() then  
8.	        --os estimates  
9.	        if os_next then  
10.	            os 
11.	        else  
12.	            false  
13.	        endif  
14.	    else  
15.	        if application_next then  
16.	        --application estimates  
17.	            application
18.	        else  
19.	            false  
20.	        endif  
21.	    endif  
22.	else  
23.	    false  
24.	endif  

```
