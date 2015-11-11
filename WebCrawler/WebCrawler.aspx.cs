using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

using System.Net;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;

namespace WebCrawler
{

    public partial class WebCrawler : System.Web.UI.Page
    {
        public int urlNum; //Total number of URLs
        List<object> arrUrlStr = new List<object>(); //List of URLs

        public void findUri(Uri urlRoot, ref object result, ref int progress)
        {
            var queue = new Queue<Uri>();
            result = "Root url is :" + urlRoot;
            progress += 1;
            Thread.Sleep(1000);

            queue.Enqueue(urlRoot);
            arrUrlStr.Add(urlRoot);

            //get the base url
            Uri uri = new Uri(urlRoot.ToString());
            string baseUrl = uri.GetLeftPart(UriPartial.Authority);
            string hostName = uri.Host;

            string Rstring;

            while (queue.Count > 0)
            {

                Uri url = queue.Dequeue();

                HttpWebRequest HttpWReq = (HttpWebRequest)WebRequest.Create(url);    // Create a request for the URL.
                HttpWebResponse HttpWResp;

                try
                {
                    HttpWResp = (HttpWebResponse)HttpWReq.GetResponse();       //Get the response.
                    Stream ReceiveStream = HttpWResp.GetResponseStream();      //Get the stream associated with the response.
                    StreamReader readStream = new StreamReader(ReceiveStream); //Pipes the stream to a higher level stream reader. 
                    Rstring = readStream.ReadToEnd();                          //Reads it to the end.

                    //URL regular expression in C#
                    Regex regex = new Regex("(?<=<a\\s*?href=(?:'|\"))[^'\"]*?(?=(?:'|\"))");

                    string href;
                    foreach (Match match in regex.Matches(Rstring))
                    {
                        if (!string.IsNullOrEmpty(match.Value))
                        {
                            //Discard files and documents
                            Regex regexObj = new Regex(@"(css|jpg|pdf|doc|docx|ppt|pptx|js|png|ico|zip)");
                            Match matchResult = regexObj.Match(match.Value);
                            if (matchResult.Success)
                            {
                                continue;
                            }

                            try
                            {
                                Uri tempUrl = new Uri(match.Value, UriKind.RelativeOrAbsolute);
                                if (urlRoot.IsBaseOf(tempUrl))
                                {
                                    href = "";
                                    if (!match.Value.Contains(baseUrl))
                                    {
                                        href = baseUrl + "/" + match.Value;
                                    }
                                    else
                                    {
                                        href = match.Value;
                                    }

                                    Uri urlNext = new Uri(href, UriKind.RelativeOrAbsolute);

                                    if (!arrUrlStr.Contains(urlNext))
                                    {
                                        arrUrlStr.Add(urlNext);
                                        queue.Enqueue(urlNext);
                                        result = urlNext.ToString();
                                        progress += 1;
                                        Thread.Sleep(1000);
                                        //Console.WriteLine(urlNext.ToString());
                                        urlNum++;

                                    }
                                }

                            }
                            catch (Exception)//UriFormatException
                            {
                                Console.WriteLine("INVALID URI!!");
                            }
                        }
                    }
                    // Clean up the streams and the response.
                    ReceiveStream.Close();
                    readStream.Close();
                    HttpWResp.Close();
                }
                catch (WebException ex)
                {
                    HttpWResp = ex.Response as HttpWebResponse;
                    result = ex.Message;
                    progress += 1;

                    //Console.WriteLine("HELL!!! Response Error 404 happened!!");
                }
            }

            result = string.Format("Crawling finished!!Total number of URl is {0}", urlNum);

        }
    }
}