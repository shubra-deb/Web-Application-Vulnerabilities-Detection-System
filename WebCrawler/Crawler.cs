using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

using System.Net;
using System.IO;
using System.Text.RegularExpressions;

using System.Collections.Specialized;
using System.Threading;
using System.Text;
using System.Web.UI.HtmlControls;
using HtmlAgilityPack;
using System.Threading.Tasks;
using System.ComponentModel;

namespace WebCrawler
{
    public class Crawler
    {
        //BackgroundWorker workerSQL = new BackgroundWorker();

        public static int urlNum; //Total number of URLs       

        public static void findUri(Uri urlRoot)
        {
            //result = "Crawling Links started.....";
            Thread.Sleep(100);
            var queue = new Queue<Uri>();
            List<object> arrayUrlStr = new List<object>();
            queue.Enqueue(urlRoot);
            arrayUrlStr.Add(urlRoot);

            //get the base url
            Uri uri = new Uri(urlRoot.ToString());
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
                                if (urlRoot.IsBaseOf(tempUrl)) //If URL of that site
                                {
                                    if (!value.Contains("http:"))
                                    {
                                        Uri baseUri = new Uri(urlRoot.ToString());
                                        Uri absoluteUri = new Uri(baseUri, value);
                                        value = absoluteUri.ToString();
                                    }
                                    //}
                                    //Uri urlNext = new Uri(value, UriKind.RelativeOrAbsolute);
                                    if (arrUrlStr.Contains(value)) continue;

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
                                                //arrUrlStr.Add(value);
                                                //result = "Link found: " + value;
                                                Thread.Sleep(100);
                                                urlNum++;
                                            }
                                            else
                                            {
                                                //result = response.StatusDescription;
                                            }
                                        }
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
                                //result = "Invalid Uri";
                            }
                        }
                    }
                }
                catch
                {
                    //result = "Html Error";
                    //remove it from arrUrlStr if exist
                    //if (arrUrlStr.Contains(value)) remove state
                    ///
                    /// If downloading times out, just ignore...
                    /// 
                }
            }
            #endregion

            //progress = 100;
            //result = "Crawling done";
        }
    }
       
}