## Troubleshooting MarkLogic External Security (LDAP and Active Directory)

## Introduction

MarkLogic allows you to configure MarkLogic Server so that users are authenticated using an external authentication protocol, such as Lightweight Directory Access Protocol (LDAP) or Kerberos. These external agents serve as centralized points of authentication or repositories for user information from which authorization decisions can be made.

This article will attempt to give some guidance on how to troubleshoot those connection issues that occur after you have configured MarkLogic server for External Authentcation using LDAP or Active Directory. As far as possible I will avoid repeating what is already in the MarkLogic documentation and to that end I would highly recommend that you make yourself familar with the following online documentation.
 
 * [MarkLogic Authentication](https://docs.marklogic.com/guide/security/authentication)
 * [MarkLogic External Authentication](https://docs.marklogic.com/guide/security/external-auth)
 
 
 Rather I will be looking more in depth at how MarkLogic works under the covers with regards External Authentication, what it is doing when it communicates with an LDAP or Active Directory server and some useful tools that will hopefully help you diagnose what exactly is going wrong.
 
 MarkLogic provides for a varied array of external authentication methods as described below and I hope to cover them all with this article, however if there is something specific that is not covered please let me know and I will do my best to make the neccessary updates.
 
 * External LDAP Users mapped to internal users
 * External LDAP users mapped to internal roles using temporary userids.
 * Certificate based authentication mapping X509 Common Name to internal users.
 * Certificate based authentication mapping X509 Distinguished Name to internal Users.
 * Certificate based authentication mapping X509 Distinguished Name to internal roles.
 * Mixed Internal and External Authentication.
 
 **Note:** Certificate based authentication methods are only available in [MarkLogic 9](https://docs.marklogic.com/guide/security/authentication#id_28959)
 
 ## Useful Tools
 
 Although this section is titled useful tools, I'd go so far as to say the following are essential tools if you are serious about diagnosing LDAP and Active Directory issues when attempting to use MArkLogic External Security.
 
 ## First Principles
 
 Before getting started it is really import to understand how the MarkLogic External Security logic flow works to help dispell any preconceived misconceptions early on. Many products use LDAP or Active Directory to control access and not all follow the same way of working
  
  ![Image](./images/MarkLogicExternalSecurityLogic.svg)
 
 
 
 
 
 

