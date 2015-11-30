# ADFS Claim Transformation #

This project aims to provide tools for manipulation of Microsoft Active Directory Services<sup>*)</sup> (ADFS) claims through so-called custom claim transformation modules.

Microsoft's documentation on custom claim transformation modules is here:
http://msdn.microsoft.com/en-us/library/bb736228(VS.85).aspx

Currently the project offers a custom claim transformation module that supports the following transformations:

  1. global claims: useful when you want to add a claim for every user that authenticates to your ADFS server while avoid having to add that attribute for every user in your AD
  1. group claim mapping: useful when you want to transform a Group claim into an Custom claim with a name that is different from "Group" (the default mapping)
  1. group authorization: when you want to deny/allow ADFS authentication at the Account Partner, based on Group membership


---

<sup>*)</sup> Microsoft Active Directory Services is the implementation of the WS-Federation 1.x standard for federated Identity Management.