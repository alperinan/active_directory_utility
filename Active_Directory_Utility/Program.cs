using System;
using ActiveDirectoryUtilities;

namespace Active_Directory_Utility
{
    class Program
    {
        //sample usage of functions

        static void Main(string[] args)
        {
            //let's create the instance
            AdData ADdata = new AdData();

            //this function takes User_Id (string) as parameter and returns a boolean value showing user is active or not
            bool IsUserActive = ADdata.IsUserActive("User_Id");

            //this function takes User_Id (string) as parameter and returns an enum result showing user status: enabled, disabled or deleted
            AccountStatus UserAccountStatus = ADdata.GetActiveDirectoryStatusBySamAccountName("User_Id");


        }

    }
}
