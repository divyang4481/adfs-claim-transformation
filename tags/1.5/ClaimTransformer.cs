using System;
using System.Configuration;
using System.Web.Security.SingleSignOn;
using System.Web.Security.SingleSignOn.Authorization;

namespace ClaimTransformer
{
  public class MappingConfigurationElement : ConfigurationElement
  {
    [ConfigurationProperty("Name", IsRequired = true)]
    public string Name
    {
      get { return this["Name"] as string; }
    }

    [ConfigurationProperty("Value", IsRequired = true)]
    public string Value
    {
      get { return this["Value"] as string; }
    }
  }

  public class GroupMappingConfigurationElement : MappingConfigurationElement
  {
    [ConfigurationProperty("Group", IsRequired = true)]
    public string Group
    {
      get { return this["Group"] as string; }
    }
  }

  public class GroupAuthorizationConfigurationElement : ConfigurationElement
  {
    [ConfigurationProperty("Group", IsRequired = true)]
    public string Group
    {
      get { return this["Group"] as string; }
    }
  }

  public class PrefixConfigurationElement : MappingConfigurationElement
  {
  }

  public class ClaimbuilderConfigurationElement : ConfigurationElement
  {
    [ConfigurationProperty("Key", IsRequired = true, IsKey = true)]
    public string Key
    {
      get { return this["Key"] as string; }
    }

    [ConfigurationProperty("ClaimValue", IsRequired = false, IsKey = false)]
    public string ClaimValue
    {
      get { return this["ClaimValue"] as string; }
    }

    [ConfigurationProperty("StringValue", IsRequired = false, IsKey = false)]
    public string StringValue
    {
      get { return this["StringValue"] as string; }
    }
  }

  public class GlobalMappingCollection : ConfigurationElementCollection
  {

    public MappingConfigurationElement this[int index]
    {
      get { return base.BaseGet(index) as MappingConfigurationElement; }
      set
      {
        if (base.BaseGet(index) != null)
        {
          base.BaseRemoveAt(index);
        }
        this.BaseAdd(index, value);
      }
    }

    protected override object GetElementKey(ConfigurationElement element)
    {
      return element.GetHashCode();
    }

    protected override ConfigurationElement CreateNewElement()
    {
      return new MappingConfigurationElement();
    }
  }

  public class GroupMappingCollection : ConfigurationElementCollection
  {

		public GroupMappingConfigurationElement this[int index]
    {
      get { return base.BaseGet(index) as GroupMappingConfigurationElement; }
      set
      {
        if (base.BaseGet(index) != null)
        {
          base.BaseRemoveAt(index);
        }
        this.BaseAdd(index, value);
      }
    }

    protected override object GetElementKey(ConfigurationElement element)
    {
      return element.GetHashCode();
    }

    protected override ConfigurationElement CreateNewElement()
    {
      return new GroupMappingConfigurationElement();
    }
  }

  public class PrefixCollection : ConfigurationElementCollection
  {
    public PrefixConfigurationElement this[int index]
    {
      get { return base.BaseGet(index) as PrefixConfigurationElement; }
      set
      {
        if (base.BaseGet(index) != null)
        {
          base.BaseRemoveAt(index);
        }
        this.BaseAdd(index, value);
      }
    }

    protected override object GetElementKey(ConfigurationElement element)
    {
      return element.GetHashCode();
    }

    protected override ConfigurationElement CreateNewElement()
    {
      return new PrefixConfigurationElement();
    }
  }

  public class ClaimbuilderCollection : ConfigurationElementCollection
  {
    [ConfigurationProperty("ClaimName", IsRequired = true)]
    public string ClaimName
    {
      get { return this["ClaimName"] as string; }
    }

    public ClaimbuilderConfigurationElement this[int index]
    {
      get { return (ClaimbuilderConfigurationElement)base.BaseGet(index); }
      set
      {
        if (base.BaseGet(index) != null)
        {
          base.BaseRemoveAt(index);
        }
        this.BaseAdd(index, value);
      }
    }

    protected override object GetElementKey(ConfigurationElement element)
    {
      return element.GetHashCode();
    }

    protected override ConfigurationElement CreateNewElement()
    {
      return new ClaimbuilderConfigurationElement();
    }
  }

  public class GroupAuthorizationCollection : ConfigurationElementCollection
  {
    [ConfigurationProperty("Mode", IsRequired = true)]
    public string Mode
    {
      get { return this["Mode"] as string; }
    }

    [ConfigurationProperty("Message", IsRequired = true)]
    public string Message
    {
      get { return this["Message"] as string; }
    }

    public GroupAuthorizationConfigurationElement this[int index]
    {
      get { return base.BaseGet(index) as GroupAuthorizationConfigurationElement; }
      set
      {
        if (base.BaseGet(index) != null)
        {
          base.BaseRemoveAt(index);
        }
        this.BaseAdd(index, value);
      }
    }

    protected override object GetElementKey(ConfigurationElement element)
    {
      return element.GetHashCode();
    }

    protected override ConfigurationElement CreateNewElement()
    {
      return new GroupAuthorizationConfigurationElement();
    }
  }

  public class RulesConfiguration : ConfigurationSection
  {
    [ConfigurationProperty("GlobalMappings")]
    public GlobalMappingCollection GlobalMappings
    {
      get { return this["GlobalMappings"] as GlobalMappingCollection; }
    }

    [ConfigurationProperty("GroupMappings")]
    public GroupMappingCollection GroupMappings
    {
      get { return this["GroupMappings"] as GroupMappingCollection; }
    }

    [ConfigurationProperty("GroupAuthorization")]
    public GroupAuthorizationCollection GroupAuthorization
    {
      get { return this["GroupAuthorization"] as GroupAuthorizationCollection; }
    }

    [ConfigurationProperty("Prefixes")]
    public PrefixCollection Prefixes
    {
      get { return this["Prefixes"] as PrefixCollection; }
    }

    [ConfigurationProperty("Claimbuilder")]
    public ClaimbuilderCollection Claimbuilder
    {
      get { return this["Claimbuilder"] as ClaimbuilderCollection; }
    }
  }

  public class ClaimTransformer : IClaimTransform
  {

    RulesConfiguration m_rules = null;

    public ClaimTransformer()
    {
      m_rules = System.Configuration.ConfigurationManager.GetSection("ClaimTransformer") as RulesConfiguration;
    }

    public void TransformClaims(
      ref SecurityPropertyCollection incomingClaims,
      ref SecurityPropertyCollection corporateClaims,
      ref SecurityPropertyCollection outgoingClaims,
      ClaimTransformStage transformStage,
      string strIssuer,
      string strTargetURI)
    {

      if (m_rules == null)
        // no processing rules have been configured
        return;

      if (incomingClaims != null)
      // we are not an Account Partner, but a resource partner
      	return;

      if (transformStage != ClaimTransformStage.PostProcessing)
        // we are not (yet) in the right phase
        return;

      foreach (MappingConfigurationElement e in m_rules.GlobalMappings)
      {
        if (outgoingClaims == null) outgoingClaims = new SecurityPropertyCollection();
        outgoingClaims.Add(SecurityProperty.CreateCustomClaimProperty(e.Name, e.Value));
      }

      if (corporateClaims == null)
        return;

      if (m_rules.GroupAuthorization != null)
      {
        bool hasMatch = false;
        foreach (SecurityProperty securityProperty in corporateClaims)
        {
          foreach (GroupAuthorizationConfigurationElement e in m_rules.GroupAuthorization)
          {
            if (securityProperty.Equals(SecurityProperty.CreateGroupProperty(e.Group)))
            {
              hasMatch = true;
            }
          }
        }

        if (m_rules.GroupAuthorization.Mode == "include")
        {
          if (hasMatch == false) throw new ApplicationException(m_rules.GroupAuthorization.Message);
        }
        else if (m_rules.GroupAuthorization.Mode == "exclude")
        {
          if (hasMatch == true) throw new ApplicationException(m_rules.GroupAuthorization.Message);
        }
      }

      foreach (SecurityProperty securityProperty in corporateClaims)
      {
        foreach (GroupMappingConfigurationElement e in m_rules.GroupMappings)
        {
          if (securityProperty.Equals(SecurityProperty.CreateGroupProperty(e.Group)))
          {
            if (outgoingClaims == null) outgoingClaims = new SecurityPropertyCollection();
            outgoingClaims.Add(SecurityProperty.CreateCustomClaimProperty(e.Name, e.Value));
          }
        }

        foreach (PrefixConfigurationElement e in m_rules.Prefixes)
        {
          if (securityProperty.Name.Equals(e.Name))
          {
            string value = e.Value + securityProperty.Value;
            outgoingClaims.Add(
              SecurityProperty.CreateCustomClaimProperty(e.Name, value));
          }
        }
      }
      
      //Build a new claim with configured claimattributes and strings
      string claimbuilderValue = string.Empty;
      foreach (ClaimbuilderConfigurationElement e in m_rules.Claimbuilder)
      {
        if (!string.IsNullOrEmpty(e.ClaimValue))
        {
          //check if the claim uri exists in the collection.
          SecurityPropertyCollection tempCollection = corporateClaims.GetCustomProperties(e.ClaimValue);
          //claim found extract value and add to claimbuilderValue.
          if (tempCollection.Count == 1)
          {
            claimbuilderValue = claimbuilderValue + tempCollection[0].Value;
          }
        }
        else if (!string.IsNullOrEmpty(e.StringValue))
        {
          claimbuilderValue = claimbuilderValue + e.StringValue;
        }
      }
      if (!string.IsNullOrEmpty(claimbuilderValue)) {
         outgoingClaims.Add(
    	    SecurityProperty.CreateCustomClaimProperty(m_rules.Claimbuilder.ClaimName, claimbuilderValue));
      }
      
    }

    private void displayClaims(SecurityPropertyCollection securityPropertyCollection)
    {
      foreach (SecurityProperty securityProperty in securityPropertyCollection)
      {
        if (securityProperty.ClaimType.Equals(WebSsoClaimType.Custom))
        {
          Console.WriteLine("Custom claim name: {0} - value: {1}",
                            securityProperty.Name, securityProperty.Value);
        }
        else if (securityProperty.ClaimType.Equals(WebSsoClaimType.Upn))
        {
          Console.WriteLine("UPN - {0}", securityProperty.Value);
        }
        else if (securityProperty.ClaimType.Equals(WebSsoClaimType.Email))
        {
          Console.WriteLine("Email - {0}", securityProperty.Value);
        }
        else if (securityProperty.ClaimType.Equals(WebSsoClaimType.CommonName))
        {
          Console.WriteLine("Common Name - {0}", securityProperty.Value);
        }
        else if (securityProperty.ClaimType.Equals(WebSsoClaimType.Group))
        {
          Console.WriteLine("Group - {0}", securityProperty.Value);
        }
      }
    }

    public static void Main(string[] args)
    {
      Console.WriteLine(" # start");
      SecurityPropertyCollection incomingClaims = new SecurityPropertyCollection();
      SecurityPropertyCollection corporateClaims = new SecurityPropertyCollection();
      SecurityPropertyCollection outgoingClaims = new SecurityPropertyCollection();
      ClaimTransformStage transformStage = ClaimTransformStage.PostProcessing;
      string strIssuer = null;
      string strTargetURI = null;

      corporateClaims.Add(SecurityProperty.CreateGroupProperty("Administrators"));
 
      ClaimTransformer o = new ClaimTransformer();
      o.TransformClaims(ref incomingClaims, ref corporateClaims, ref outgoingClaims, transformStage, strIssuer, strTargetURI);

      o.displayClaims(outgoingClaims);

      Console.WriteLine(" # end");
    }
  }
}