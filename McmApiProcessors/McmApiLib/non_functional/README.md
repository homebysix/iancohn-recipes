Objects in this folder are non-functional, but kept here for reference.

### McmContentDistributer

This doesn't appear possible, given the contents of the result from 

```TEXT
GET /AdminService/wmi/$metadata
GET /AdminService/v1.0/$metadata
```

It is apparently not possible to distribute or re-distribute content. In fact, several of the WMI methods which are [documented](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/configuration-manager-reference) are similarly not exposed by AdminService. If you wish to see if your wmi method *is* available, query the metadata (above), and search for \<YourObjectName\>.\<YourMethod\> (ex. SMS_ContentPackage.GetNextId). If there are no results, the method is not exposed via the Admin Service.

My hypothesis is that this has roughly to do with the parameters on the method and whether the instance targeted with the method is called out in the parameters submitted in the body, as is the case with SMS_SecuredCategoryMembership.AddMemberships, or the method assumes that the endpoint itself *is* the target, as is the case with SMS_Application.SetIsExpired, which does not work.