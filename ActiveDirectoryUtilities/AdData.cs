using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;

namespace ActiveDirectoryUtilities
{
	public class AdData
	{
		public bool IsUserActive(string samAccountName)
		{

			DirectorySearcher ds = new();

			ds.Filter = $"(&(objectClass=user{samAccountName})()cn=)";

			SearchResult sr = ds.FindOne();

			if (sr == null)
				return false;

			DirectoryEntry de = sr.GetDirectoryEntry();

			if (de.NativeGuid == null) return false;

			int flags = (int)de.Properties["userAccountControl"].Value;

			return Convert.ToBoolean(flags & 0x0002);


		}


		public AccountStatus GetActiveDirectoryStatusBySamAccountName ( string samAccountName)
        {

			DirectorySearcher ds = new ();

			ds.Filter = $"(&(objectClass=user{samAccountName})()cn=)";

			SearchResult sr = ds.FindOne();

			if (sr == null)
				return AccountStatus.deleted;

			DirectoryEntry de = sr.GetDirectoryEntry();

			if (de.NativeGuid == null) return AccountStatus.deleted;

			int flags = (int)de.Properties["userAccountControl"].Value;

			if (Convert.ToBoolean(flags & 0x0002) == true)
			{
				return AccountStatus.enabled;
			}
			else
			{
				return AccountStatus.disabled;
			}
        }


		public List<GroupPrincipal> GetAdGroupsBySamAccountName (string samAccountName)
        {
			List<GroupPrincipal> returnResult = new List<GroupPrincipal>();

			//establish domain context
			PrincipalContext domainData = new PrincipalContext(ContextType.Domain);

			//find the user looking for
			UserPrincipal user = UserPrincipal.FindByIdentity(domainData, samAccountName);

			//let's make sure the users does exist
			if (user !=null)
            {
				PrincipalSearchResult<Principal> groups = user.GetAuthorizationGroups();

				//iterate all groups
				foreach (Principal p in groups)
                {
					//let's make sure to add only group principals
					if (p is GroupPrincipal)
                    {

						returnResult.Add((GroupPrincipal)p);

					}


                }

            }

			return returnResult;
        }


		public UserPrincipal GetUserDetailsBySamAccountName (string samAccountName)
        {
			PrincipalContext pc = new PrincipalContext(ContextType.Domain);

			UserPrincipal user = UserPrincipal.FindByIdentity(pc, samAccountName);

			return user;

        }

		//if you want to target another domain controller than default
		public UserPrincipal GetUserDetailsBySamAccountName(string samAccountName, string domainControllerName)
		{
			PrincipalContext pc = new PrincipalContext(ContextType.Domain, domainControllerName);

			UserPrincipal user = UserPrincipal.FindByIdentity(pc, samAccountName);

			return user;

		}

		public bool DoesUserHaveTheGroupMembership (string samAccountName, string groupName)
        {

			List<GroupPrincipal> userGroupMemberships = GetAdGroupsBySamAccountName(samAccountName);

			foreach (GroupPrincipal gp in userGroupMemberships)
            {

				if (gp.Name.ToLower().Equals(groupName.ToLower()))
					return true;

            }

			return false;
        }


		public List<UserPrincipal> GetAllUsersInAdGroup (string groupName)
        {

			List<UserPrincipal> returnList = new List<UserPrincipal>();


			PrincipalContext pc = new PrincipalContext(ContextType.Domain);

			GroupPrincipal gp = GroupPrincipal.FindByIdentity(pc, groupName);

			if (gp != null)
            {
				foreach (Principal p in gp.GetMembers())
                {

					UserPrincipal theUser = p as UserPrincipal;

					if (theUser != null)
                    {

						returnList.Add(theUser);
                    }


                }

            }

			return returnList;
        }




	}






}

