using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

using System.Net;
using System.IO;
using System.Text.RegularExpressions;

using System.Collections.Specialized;
using System.Threading;
using System.Text;
using System.Web.UI.HtmlControls;
using HtmlAgilityPack;
using System.Threading.Tasks;


namespace WebCrawler
{
    public partial class _Default : System.Web.UI.Page
    {
        public static int urlNum; //Total number of URLs
        string result = "";
        int indexSoFarXSS = 0;
        int indexSoFar = 0;

        BackgroundWorker workerCrawler;
        BackgroundWorker workerSQL;
        BackgroundWorker workerSQLAuth;
        BackgroundWorker workerRXSS;
        BackgroundWorker workerSXSS;

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Page.IsPostBack)
            {
                Timer1.Enabled = false;
            }
        }

        protected void Button1_Click(object sender, EventArgs e)
        {
            lbWarning.Text = string.Empty;

            showExtractContent.InnerHtml = string.Empty;
            showExtractContentXSS.InnerHtml = string.Empty;

            indexSoFarXSS = 0;
            indexSoFar = 0;

            string URL = txtURL.Text;

            List<string> linksSQLVulnerable = new List<string>();
            List<string> linksSQLAuthVulnerable = new List<string>();
            List<string> linksCrawled = new List<string>();
            List<string> linksXSS = new List<string>();

            int selectedCount = CheckBoxList1.Items.Cast<ListItem>().Count(li => li.Selected);


            if (txtURL.Text != string.Empty)
            {
                if (selectedCount > 0)
                {
                    workerCrawler = new BackgroundWorker();
                    workerCrawler.DoWork += new BackgroundWorker.DoWorkEventHandler(workerCrawler_DoWork);
                    workerCrawler.RunWorker(URL);

                    for (int i = 0; i < CheckBoxList1.Items.Count; i++)
                    {
                        if (CheckBoxList1.Items[i].Selected)
                        {
                            string name = CheckBoxList1.Items[i].Text;
                            switch (name)
                            {
                                case "Standard SQL Injection":
                                    workerSQL = new BackgroundWorker();
                                    workerSQL.DoWork += new BackgroundWorker.DoWorkEventHandler(workerSQL_DoWork);
                                    workerSQL.RunWorker(linksCrawled);
                                    break;
                                case "Broken Authentication using SQL Injection": 
                                    workerSQLAuth = new BackgroundWorker(); 
                                    workerSQLAuth.DoWork += new BackgroundWorker.DoWorkEventHandler(workerSQLAuth_DoWork);
                                    workerSQLAuth.RunWorker(linksCrawled); break;
                                case "Reflected Cross-Site Scripting": 
                                    workerRXSS = new BackgroundWorker(); 
                                    workerRXSS.DoWork += new BackgroundWorker.DoWorkEventHandler(workerRXSS_DoWork);
                                    workerRXSS.RunWorker(linksCrawled); break;
                                case "Stored Cross-Site Scripting": 
                                    workerSXSS = new BackgroundWorker(); break;
                            }
                        }
                    }

                    // Enable the timer to update the status of the operation.
                    Timer1.Enabled = workerCrawler.IsRunning;
                }
                else
                {
                    lbWarning.Text = "Please choose vulnerability scan option!!";
                }
            }
            else
            {
                lbWarning.Text = "Please enter a URL to scan";
            }

            // It needs Session Mode is "InProc"
            // to keep the Background Worker working.
            Session["workerCrawler"] = workerCrawler;
            Session["workerSQL"] = workerSQL;
            Session["workerRXSS"] = workerRXSS;
            Session["workerSQLAuth"] = workerSQLAuth;

            Session["linksSQLVulnerable"] = linksSQLVulnerable;
            Session["linksSQLAuthVulnerable"] = linksSQLAuthVulnerable;
            Session["linksXSS"] = linksXSS;
            Session["linksCrawled"] = linksCrawled;

        }

        void workerCrawler_DoWork(ref int progress,
           ref string result, ref List<string> array, params object[] args)
        {
            array = new List<string>();
            List<string> invalidLinks = new List<string>();
            // Get the value which passed to this operation.

            string urlToCheck = string.Empty;
            Uri startingUri = new Uri(args[0].ToString());

            result = "Crawling Links started.....";
            Thread.Sleep(100);
            var queue = new Queue<Uri>();

            queue.Enqueue(startingUri);
            array.Add(startingUri.ToString());

            //get the base url
            Uri uri = new Uri(startingUri.ToString());
            string baseUrl = uri.GetLeftPart(UriPartial.Authority);
            string hostName = uri.Host;

            string Rstring;

            #region queue
            while (queue.Count > 0)
            {
                string sUrl = queue.Dequeue().ToString();
                try
                {
                    string html = new WebClient().DownloadString(sUrl);

                    //if html file is empty if (html.Length == 0) { continue; }

                    MatchCollection matches = Regex.Matches(html, "href[ ]*=[ ]*['|\"][^\"'\r\n]*['|\"]");
                    //MatchCollection matches = Regex.Matches(html, "(?<=<a\\s*?href=(?:'|\"))[^'\"]*?(?=(?:'|\"))");
                    foreach (Match match in matches)
                    {
                        string value = match.Value;
                        value = Regex.Replace(value, "(href[ ]*=[ ]*')|(href[ ]*=[ ]*\")", string.Empty);
                        if (value.EndsWith("\"") || value.EndsWith("'"))
                            value = value.Remove(value.Length - 1, 1);
                        if (!Regex.Match(value, @"\((.*)\)").Success)
                        {
                            try
                            {
                                Uri tempUrl = new Uri(value, UriKind.RelativeOrAbsolute);
                                if (startingUri.IsBaseOf(tempUrl)) //If URL of that site
                                {
                                    if (!value.Contains("http:"))
                                    {
                                        Uri baseUri = new Uri(startingUri.ToString());
                                        Uri absoluteUri = new Uri(baseUri, value);
                                        value = absoluteUri.ToString();
                                    }
                                    //}
                                    //Uri urlNext = new Uri(value, UriKind.RelativeOrAbsolute);
                                    if (array.Contains(value)) continue;
                                    if (invalidLinks.Contains(value)) continue;

                                    //Discard following types of files
                                    Regex invalidType = new Regex(@"(css|jpg|gif|pdf|doc|docx|ppt|pptx|js|png|ico|zip|xls|txt|exe)");
                                    Match matchResult = invalidType.Match(value);
                                    if (!matchResult.Success)
                                    {
                                        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(value);
                                        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                                        {
                                            if (response.StatusCode == HttpStatusCode.OK)
                                            {
                                                queue.Enqueue(new Uri(value));
                                                array.Add(value);
                                                result = "Link found: " + value;
                                                Thread.Sleep(100);
                                                urlNum++;
                                            }
                                            else
                                            {
                                                result = response.StatusDescription;
                                                invalidLinks.Add(value);
                                            }
                                        }

                                        Session["linksCrawled"] = array;
                                    }


                                    /*
                                        var thread = new Thread(ProcessWebRequests);
                                        threadList.Add(thread);
                                        thread.Start();
                                    */
                                    //ThreadFunction(value);     
                                }

                            }

                            catch (Exception)//UriFormatException
                            {
                                result = "Invalid Uri";
                            }
                        }
                    }
                }
                catch
                {
                    result = "Html Error";
                    //remove it from arrUrlStr if exist
                    //if (arrUrlStr.Contains(value)) remove state
                    ///
                    /// If downloading times out, just ignore...
                    /// 
                }
            }
            #endregion

            progress = 100;
            result = "Crawling done";

        }

        void workerSQL_DoWork(ref int progress,
           ref string result, ref List<string> array, params object[] args)//its array stores list of vulnerable links
        {
            List<string> linksCrawled = (List<string>)Session["linksCrawled"];
            array = (List<string>)Session["linksSQLVulnerable"];

            int currentIndex = indexSoFar;
            for (; linksCrawled!=null && currentIndex < linksCrawled.Count; currentIndex++)
            {
                string urlToCheck = linksCrawled[currentIndex];

                //Start SQL Injection Test Function
                result = "Starting SQL Injection test function on : " + urlToCheck;
                Thread.Sleep(1000);

                Sql.DetectSql(urlToCheck, ref result, ref array);
                Session["linksSQLVulnerable"] = array;

                indexSoFar = currentIndex;
                if (Session["workerCrawler"] == null)
                {
                    currentIndex = indexSoFar;
                }
            }
            indexSoFar = currentIndex;
            if (indexSoFar != 0 && indexSoFar == linksCrawled.Count)
            {
                progress = 101;
                workerSQL.Abort();
            }
            else
            {
                progress = 100;
            }
            Thread.Sleep(100);
            //result = "Operation is completed. The input is \"" + urlToCheck + "\".";
        }

        int indexSoFarAuth = 0;
        void workerSQLAuth_DoWork(ref int progress,
           ref string result, ref List<string> array, params object[] args)//its array stores list of vulnerable links
        {
            List<string> linksCrawled = (List<string>)Session["linksCrawled"];
            array = (List<string>)Session["linksSQLAuthVulnerable"];

            int currentIndexAuth = indexSoFarAuth;
            for (; linksCrawled != null && currentIndexAuth < linksCrawled.Count; currentIndexAuth++)
            {
                string urlToCheck = linksCrawled[currentIndexAuth];

                //Start SQL Injection Test Function
                result = "Starting SQL Injection test function on : " + urlToCheck;
                Thread.Sleep(1000);

                Sql.AuthenticationSql(urlToCheck, ref result, ref array);//Sql.DetectSql(urlToCheck, ref result, ref array);
                Session["linksSQLAuthVulnerable"] = array;

                indexSoFar = currentIndexAuth;
                if (Session["workerCrawler"] == null)
                {
                    currentIndexAuth = indexSoFarAuth;
                }
            }
            //indexSoFar = currentIndex;
            if (indexSoFarAuth != 0 && indexSoFarAuth == linksCrawled.Count)
            {
                progress = 101;
                workerSQLAuth.Abort();
            }
            else
            {
                progress = 100;
            }
            Thread.Sleep(100);
            //result = "Operation is completed. The input is \"" + urlToCheck + "\".";
        }


        void workerRXSS_DoWork(ref int progress,
          ref string result, ref List<string> array, params object[] args)
        {
            List<string> linksCrawled = (List<string>)Session["linksCrawled"];
            int currentIndexXSS = indexSoFarXSS;
            array = (List<string>)Session["linksXSS"];

            for (; linksCrawled != null && currentIndexXSS < linksCrawled.Count; currentIndexXSS++)
            {
                progress = 0;
                string urlToCheck = linksCrawled[currentIndexXSS];

                Xss.DetectXss(urlToCheck, ref result, ref array);
                Session["linksXSS"] = array;

                indexSoFarXSS = currentIndexXSS;
                if (Session["workerCrawler"] == null)
                {
                    currentIndexXSS = indexSoFarXSS;
                }
            }
            indexSoFarXSS = currentIndexXSS;
            if (Session["workerCrawler"] == null && indexSoFarXSS != 0 && indexSoFarXSS == linksCrawled.Count)
            {
                progress = 101;
                workerRXSS.Abort();
            }
            else
            {
                progress = 100;
                result = "Waiting for crawler....";
            }

            //result = "Operation is completed. The input is \"" + urlToCheck + "\".";
        }

        protected void Timer1_Tick(object sender, EventArgs e)
        {
            // Show the progress of current operation.
            BackgroundWorker workerCrawler = (BackgroundWorker)Session["workerCrawler"];
            BackgroundWorker workerSQL = (BackgroundWorker)Session["workerSQL"];
            BackgroundWorker workerRXSS = (BackgroundWorker)Session["workerRXSS"];
            BackgroundWorker workerSQLAuth = (BackgroundWorker)Session["workerSQLAuth"];

            List<string> linksCrawled = (List<string>)Session["linksCrawled"];
            List<string> linksSQLVulnerable = (List<string>)Session["linksSQLVulnerable"];
            List<string> linksSQLAuth = (List<string>)Session["linksSQLAuthVulnerable"];
            List<string> linksXSS = (List<string>)Session["linksXSS"];

            if (workerCrawler != null && workerCrawler.IsRunning)
                Timer1.Enabled = workerCrawler.IsRunning;
            else if (workerSQL != null && workerSQL.IsRunning)
                Timer1.Enabled = workerSQL.IsRunning;
            else if (workerSQLAuth != null && workerSQLAuth.IsRunning)
                Timer1.Enabled = workerSQLAuth.IsRunning;
            else if (workerRXSS != null && workerRXSS.IsRunning)
                Timer1.Enabled = workerRXSS.IsRunning;
            else Timer1.Enabled = false;

           
            #region workerCrawler
            if (workerCrawler != null)
            {
                // Display the progress of the operation.
                lbProgress.Text = "Crawling Status: " + workerCrawler.Result.ToString();
                lblNumCrawled.Text = linksCrawled.Count.ToString();
                btnScan.Enabled = !workerCrawler.IsRunning;

                // Display the result when the operation completed.
                if (workerCrawler.Progress >= 100)
                {
                    lbProgress.Text = (string)workerCrawler.Result;
                    Session["workerCrawler"] = null;
                    workerCrawler.Abort();
                    Thread.Sleep(1000);
                }
            }
            #endregion

            #region workerSQL
            if (workerSQL != null)
            {
                if (linksCrawled != null && linksCrawled.Count >= 1 && workerSQL.Progress == 100)
                {
                    workerSQL.DoWork += new BackgroundWorker.DoWorkEventHandler(workerSQL_DoWork);
                    workerSQL.RunWorker(linksCrawled);

                    // It needs Session Mode is "InProc"
                    // to keep the Background Worker working.
                    Session["workerSQL"] = workerSQL;
                    Session["linksSQLVulnerable"] = workerSQL.array;
                }

                lblNumVul.Text = linksSQLVulnerable.Count.ToString();

                if (workerSQL.Result.ToString().Contains("Found"))
                {
                    showExtractContent.InnerHtml += workerSQL.Result.ToString();
                }
                else
                {
                    lbSQL.Text = workerSQL.Result.ToString();
                }

                Thread.Sleep(1000);
                // GridViewLinks.DataSource = linksSQLVulnerable;
                // GridViewLinks.DataBind();

                if (workerSQL.Progress == 101)
                {
                    lbSQL.Text = "Sql detection done!";
                    // GridViewLinks.DataSource = workerSQL.array;
                    // GridViewLinks.DataBind();
                    Timer1.Enabled = false;
                }
            }
            #endregion

            #region workerRXSS
            if (workerRXSS != null)
            {
                if (linksCrawled != null && linksCrawled.Count >= 1 && workerRXSS.Progress == 100)
                {
                    workerRXSS.DoWork += new BackgroundWorker.DoWorkEventHandler(workerRXSS_DoWork);
                    workerRXSS.RunWorker(linksCrawled);

                    // It needs Session Mode is "InProc"
                    // to keep the Background Worker working.
                    Session["workerRXSS"] = workerRXSS;
                    Session["linksXSS"] = workerRXSS.array;
                }

                if (workerRXSS.Result.ToString().Contains("Reflected"))
                {
                    showExtractContentXSS.InnerHtml += workerRXSS.Result.ToString();
                }
                else
                {
                    lbXSS.Text = workerRXSS.Result.ToString();
                }
                Thread.Sleep(1000);
                lblNumVulXSS.Text = linksXSS.Count.ToString();
                // GridViewLinks.DataSource = linksXSS;
                // GridViewLinks.DataBind();

                if (workerRXSS.Progress == 101)
                {
                    lbXSS.Text = "Cross-site scripting done!";
                    // GridViewXSS.DataSource = workerRXSS.array;
                    //  GridViewXSS.DataBind();
                    Timer1.Enabled = false;
                    Thread.Sleep(1000);
                }
            }
            #endregion

            #region workerSQLAuth
            if (workerSQLAuth != null)
            {
                if (linksCrawled != null && linksCrawled.Count >= 1 && workerSQLAuth.Progress == 100)
                {
                    workerSQLAuth.DoWork += new BackgroundWorker.DoWorkEventHandler(workerSQLAuth_DoWork);
                    workerSQLAuth.RunWorker(linksCrawled);

                    // It needs Session Mode is "InProc"
                    // to keep the Background Worker working.
                    Session["workerSQLAuth"] = workerSQLAuth;
                    Session["linksSQLAuthVulnerable"] = workerSQLAuth.array;
                }

                if (workerSQLAuth.Result.ToString().Contains("Found Broken Authentication"))
                {
                    showExtractContent.InnerHtml += workerSQLAuth.Result.ToString();
                }
                else
                {
                    lbSQL.Text = workerSQLAuth.Result.ToString();
                }
                Thread.Sleep(1000);
                lblNumVul.Text = linksSQLAuth.Count.ToString();
                // GridViewLinks.DataSource = linksXSS;
                // GridViewLinks.DataBind();

                if (workerSQLAuth.Progress == 101)
                {
                    lbSQL.Text = "By-Pass Authentication SQL Injection done!";
                    // GridViewXSS.DataSource = workerRXSS.array;
                    //  GridViewXSS.DataBind();
                    Timer1.Enabled = false;
                    Thread.Sleep(1000);
                }
            }
            #endregion
        }

        protected void btnStop_Click(object sender, EventArgs e)
        {
            // Show the progress of current operation.
            BackgroundWorker workerCrawler = (BackgroundWorker)Session["workerCrawler"];
            BackgroundWorker workerSQL = (BackgroundWorker)Session["workerSQL"];
            BackgroundWorker workerRXSS = (BackgroundWorker)Session["workerRXSS"];
            BackgroundWorker workerSQLAuth = (BackgroundWorker)Session["workerSQLAuth"];

            workerCrawler.Abort();
            workerSQL.Abort();
            workerRXSS.Abort();
            workerSQLAuth.Abort();
            Session["workerCrawler"] = null;
            Session["workerSQL"] = null;
            Session["workerRXSS"] = null;
            Session["workerSQLAuth"] = null;

            Session["linksSQLVulnerable"] = null;
            Session["linksSQLAuthVulnerable"] = null;
            Session["linksXSS"] = null;
            Session["linksCrawled"] = null;

            lbProgress.Text = "Crawling stopped!";
            lbSQL.Text = "Scanning stopped!";
            lbXSS.Text = "Scanning stopped!";
            Timer1.Enabled = false;
            btnScan.Enabled = true;
        }

    }

}
