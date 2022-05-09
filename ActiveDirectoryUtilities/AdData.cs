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
		
		public List<UserPrincipal> GetAllUsersInAdGroupByGroupName (string groupName)
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

		public List<ActiveDirectoryMember> GetUsersInAdGroupIncludingNestedGroups (string groupName, HashSet<string> groupsAlreadyProcessed, string topGroupName = "")
        {

			List<ActiveDirectoryMember> returnList = new List<ActiveDirectoryMember>();

			PrincipalContext pc = new PrincipalContext(ContextType.Domain);

			GroupPrincipal gp = GroupPrincipal.FindByIdentity(pc, IdentityType.SamAccountName, groupName);

			groupsAlreadyProcessed.Add(groupName.ToLower());

			if (gp!=null)
            {

				foreach (Principal p in gp.GetMembers())
                {

					if (p.StructuralObjectClass == null)
						continue;

					if (!p.StructuralObjectClass.ToLower().Equals("user"))
                    {

						if (p.StructuralObjectClass.ToLower().Equals("group"))
                        {

							if (!groupsAlreadyProcessed.Contains(p.SamAccountName.ToLower()))
                            {

								returnList.AddRange(GetUsersInAdGroupIncludingNestedGroups(p.SamAccountName, groupsAlreadyProcessed, groupName));

								groupsAlreadyProcessed.Add(p.SamAccountName.ToLower());

                            }

                        }

                    }
					else
                    {

						UserPrincipal theUser = p as UserPrincipal;

						if (theUser != null)
                        {

							returnList.Add(new ActiveDirectoryMember(groupName, p.SamAccountName, topGroupName));
                        }



                    }




                }











            }






			return returnList;

        }

		public List<string> GetAllAdGroupNames ()
        {
			List<string> returnList = new List<string>();

			PrincipalContext pc = new PrincipalContext(ContextType.Domain);

			GroupPrincipal gp = new GroupPrincipal(pc);

			PrincipalSearcher ps = new PrincipalSearcher(gp);

			foreach (var item in ps.FindAll())
            {

				returnList.Add(item.SamAccountName);

            }

			return returnList;

        }

		public DateTime FindLatestLoginDateTimeFromAllDomainControllersBySamAccountName (string samAccountName)
        {
			DirectoryContext context = new DirectoryContext(DirectoryContextType.Domain);

			DateTime latestLogon = DateTime.MinValue;

			DomainControllerCollection dcc = DomainController.FindAll(context);

			Parallel.ForEach(dcc.Cast<object>(), dc1 =>
			{

				DirectorySearcher ds;
				DomainController dc = (DomainController)dc1;

				using (ds = dc.GetDirectorySearcher())
                {

					try
                    {

						ds.Filter = String.Format(

							"(sAMAccountName={0})",
							samAccountName
							);

						ds.PropertiesToLoad.Add("lastLogon");
						ds.SizeLimit = 1;

						SearchResult sr = ds.FindOne();

						if (sr != null)
                        {

							DateTime lastLogon = DateTime.MinValue;

							if (sr.Properties.Contains("lastLogon"))
                            {

								lastLogon = DateTime.FromFileTime(

                                    (long)sr.Properties["lastLogon"][0]

									);

                            }

							if (DateTime.Compare(lastLogon, latestLogon) > 0)
								latestLogon = lastLogon;
                        }

                    }catch
                    {

                    }





                }






			});


			return latestLogon;

        }

		public Dictionary<string, string> GetAllDomainControllersIpAddressKey ()
        {
			Dictionary<string, string> returnDict = new Dictionary<string, string>();

			var domains = Forest.GetCurrentForest().Domains;

			foreach (Domain domain in domains)
            {
				var domainName = domain.Name;

				DirectoryContext context = new DirectoryContext(DirectoryContextType.Domain, domainName);

				DomainControllerCollection dcc = DomainController.FindAll(context);

				foreach (DomainController item in dcc)
                {

					returnDict.Add(item.IPAddress, item.Name);

                }
				
            }

			return returnDict;

		}


	}






}

