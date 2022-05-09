using System;
namespace ActiveDirectoryUtilities
{
	public class ActiveDirectoryMember
	{

        public string GroupName { get; set; }
        public string SamAccountName { get; set; }
        public string TopGroupIfNested { get; set; }

        public ActiveDirectoryMember(string _GroupName, string _SamAccountName, string _TopGroupIfNested)
        {

            GroupName = _GroupName;
            SamAccountName = _SamAccountName;
            TopGroupIfNested = _TopGroupIfNested;

        }


    }
}

