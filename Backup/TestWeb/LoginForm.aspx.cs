using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Data;
using System.Data.SqlClient;

namespace TestWeb
{
    public partial class LoginForm : System.Web.UI.Page
    {
        string connectionName = "CnStr";
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void Button1_Click(object sender, EventArgs e)
        {
            SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings[connectionName].ConnectionString);
            SqlDataAdapter sda = new SqlDataAdapter("select * from Users where Username=" + "'" + txtUsername.Text + "'" + " and Password=" + "'" + txtPassword.Text + "'", con);
            DataTable dt = new DataTable();
            sda.Fill(dt);
            if (dt.Rows.Count > 0)
            {
                Response.Redirect("~/Default.aspx");
            }
            else
            {
                LabelError.Text = "Cannot login";
            }
        }
    }
}