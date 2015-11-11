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

namespace WebCrawler
{
    public class Xss
    {
        //Class
        public class FormDataStore
        {
            public string getId, getName, getMethod, getAction;
            public int getFormNum;

            public FormDataStore(string formId, string formName, string formMethod, string formAction, int formNum)
            {
                getId = formId;
                getName = formName;
                getMethod = formMethod;
                getAction = formAction;
                getFormNum = formNum;
            }
        }

        public class InputDataStore
        {
            public string iId, getName, getValue, getType, getIdOfForm, getNameOfForm;
            public int getFormNum;

            public InputDataStore(string inputId, string inputName, string formId, string formName, string inputValue, string inputType, int formNum)
            {
                iId = inputId;
                getName = inputName;
                getIdOfForm = formId;
                getNameOfForm = formName;
                getValue = inputValue;
                getType = inputType;
                getFormNum = formNum;
            }
        }

        public class PostOrGetObject
        {
            public string gpName, gpValue;

            public PostOrGetObject(string name, string value)
            {
                gpName = name;
                gpValue = value;
            }
        }

        public class MyWebRequest
        {
            private WebRequest request;
            private Stream dataStream;

            private string status;

            public String Status
            {
                get
                {
                    return status;
                }
                set
                {
                    status = value;
                }
            }

            public MyWebRequest(string url)
            {
                // Create a request using a URL that can receive a post.
                if (url.Contains("localhost"))
                {
                    url = url.Replace("localhost", "127.0.0.1");
                }
                if (!url.Contains("http://")) url = "http://" + url;
                request = WebRequest.Create(url);
            }

            public MyWebRequest(string url, string method)
                : this(url)
            {

                if (method.Equals("GET") || method.Equals("POST"))
                {
                    // Set the Method property of the request to POST.
                    request.Method = method;
                }
                else
                {
                    throw new Exception("Invalid Method Type");
                }
            }

            public MyWebRequest(string url, string method, string data)
                : this(url, method)
            {

                // Create POST data and convert it to a byte array.
                string postData = data;
                byte[] byteArray = Encoding.UTF8.GetBytes(postData);

                // Set the ContentType property of the WebRequest.
                request.ContentType = "application/x-www-form-urlencoded";

                // Set the ContentLength property of the WebRequest.
                request.ContentLength = byteArray.Length;

                // Get the request stream.
                dataStream = request.GetRequestStream();

                // Write the data to the request stream.
                dataStream.Write(byteArray, 0, byteArray.Length);

                // Close the Stream object.
                dataStream.Close();

            }

            public string GetResponse()
            {
                // Get the original response.
                WebResponse response = request.GetResponse();

                this.Status = ((HttpWebResponse)response).StatusDescription;

                // Get the stream containing all content returned by the requested server.
                dataStream = response.GetResponseStream();

                // Open the stream using a StreamReader for easy access.
                StreamReader reader = new StreamReader(dataStream);

                // Read the content fully up to the end.
                string responseFromServer = reader.ReadToEnd();

                // Clean up the streams.
                reader.Close();
                dataStream.Close();
                response.Close();

                return responseFromServer;
            }

        }

        //Submit these
        //If adding string to this array, add a corresponding string (to look for in response), with he same index, in the array below
        //The response to look for can be the same as the payload or different.
        static string[] payloads = {"<webvulscan>",
				                    "javascript:alert(webvulscan)"};

        //Look for these in response after submitting corresponding payload
        static string[] harmfulResponses = {"<webvulscan>",
				                            "src=javascript:alert(webvulscan)"};

        //Variables
        static String body;
        private static bool vulnerabilityFound;
        public static string formId, formName, formMethod, formAction;
        public static string inputId, inputName, inputValue, inputType;
        static string totalTestStr;

        //Funcation
        public static void DetectXss(string urlToCheck, ref string result, ref List<String> array)
        {
            //First check does the URL passed into this function contain parameters and submit payloads as those parameters if it does
            Uri uri = new Uri(urlToCheck);
            string query = uri.Query.Replace("?", "");
            NameValueCollection Parms = HttpUtility.ParseQueryString(query);

            result = string.Format("Check if {0} contains parameters", urlToCheck);
            Thread.Sleep(1000);

            if (Parms != null && Parms.Count > 0)
            {
                //MessageBox.Show("$urlToCheck does contain parameters");
                Thread.Sleep(1000);
                result = string.Format("{0} does contain parameters", urlToCheck);
                Thread.Sleep(1000);

                string scheme = uri.Scheme;
                string host = uri.Host;
                string path = HttpUtility.UrlDecode(uri.AbsolutePath);
                string originalQuery = query;

                int payloadIndex = 0;

                foreach (string currentPayload in payloads)
                {
                    foreach (string x in Parms.AllKeys)
                    {
                        query = originalQuery;
                        string newQuery = query.Replace(Parms[x], currentPayload);

                        query = newQuery;

                        string testUrl = scheme + "://" + host + path + '?' + query;

                        //MessageBox.Show("URL to be requested is: ",testUrl);
                        result = string.Format("URL to be requested is: " + testUrl);
                        string error;

                        HttpWebRequest myHttpWebRequest = (HttpWebRequest)WebRequest.Create(testUrl);
                        HttpWebResponse myHttpWebResponse;

                        try
                        {
                            myHttpWebResponse = (HttpWebResponse)myHttpWebRequest.GetResponse();
                            Stream receiveStream = myHttpWebResponse.GetResponseStream();
                            StreamReader reader = new StreamReader(receiveStream, Encoding.UTF8);
                            String body = reader.ReadToEnd();
                            if (body.Length > 0)
                            {
                                string indicatorStr = harmfulResponses[payloadIndex];
                                if (body.IndexOf(indicatorStr) != -1)
                                {
                                    StringBuilder str = new StringBuilder();
                                    str.Append("<br><span style='font-size:medium;font-style: bold;color:red;'>" + "Reflected XSS Present!" + "</span><br>" + "Query:" + urlToCheck + "<br>");
                                    str.Append("Method: GET <br>");
                                    str.Append("Url: " + testUrl + "<br>");
                                    str.Append("Error: " + indicatorStr + "<br>");
                                    result = str.ToString();   
                                    array.Add(str.ToString());
                                    Thread.Sleep(2000);
                                    /*
                                    showExtractConetent.InnerHtml = "<br>Reflected XSS Present!<br>Query:" + urlToCheck + "<br>";
                                    showExtractConetent.InnerHtml = "Method: GET <br>";
                                    showExtractConetent.InnerHtml = "Url: " + testUrl + "<br>";
                                    showExtractConetent.InnerHtml = "Error: " + regularExpression + "<br>";
                                     */
                                    myHttpWebResponse.Close();
                                    return;
                                }
                            }
                            myHttpWebResponse.Close();
                        }
                        catch (WebException ex)
                        {
                            myHttpWebResponse = ex.Response as HttpWebResponse;
                            result = ex.Message;
                        }
                    }
                    payloadIndex++;
                }
            }

            /*
            //begin form testing
            string actionUrl;

            var uri1 = new Uri(urlToCheck); // Find the length of the hostname
            //string urlOfSite = uri.Scheme + "://www." + uri.Host;
            string urlOfSite = uri1.Host;

            //Load the html document from the url
            var webGet = new HtmlWeb();
            HtmlNode.ElementsFlags.Remove("form");
            HtmlDocument document = webGet.Load(urlToCheck);


            List<FormDataStore> arrayOfForms = new List<FormDataStore>(); //Array containing all form objects found
            List<InputDataStore> arrayOfInputFields = new List<InputDataStore>(); //Array containing all input fields


            int formNum = 0;//Must use an integer to identify form as forms could have same names and ids

            #region Find all HtmlForms and their inputs
            HtmlNodeCollection nodeCollection = document.DocumentNode.SelectNodes("//form");
            for (int nodeNum = 0; nodeCollection != null && nodeNum < nodeCollection.Count; nodeNum++)
            {
                HtmlNode form = nodeCollection[nodeNum];
                //HtmlForm form = (HtmlForm)form.FindControl("form");
                formId = (form.Attributes["id"] != null) ? form.Attributes["id"].Value : "";
                formName = (form.Attributes["name"] != null) ? form.Attributes["name"].Value : "";
                formMethod = (form.Attributes["method"] != null) ? form.Attributes["method"].Value : "get";
                formAction = (form.Attributes["action"] != null) ? form.Attributes["action"].Value : "";

                formMethod = formMethod.ToLower();

                //If the action of the form is empty, set the action equal to everything
                //after the URL that the user entered
                if (String.IsNullOrEmpty(formAction))
                {
                    int strLengthUrl = urlToCheck.Length;
                    int strLengthSite = urlOfSite.Length;
                    int firstIndexOfSlash = urlToCheck.IndexOf('/', strLengthSite - 1);
                    formAction = urlToCheck.Substring(firstIndexOfSlash + 1, strLengthUrl);
                }

                FormDataStore newArr = new FormDataStore(formId, formName, formMethod, formAction, formNum);
                arrayOfForms.Add(newArr);
                HtmlNodeCollection nodeCollectionInput = form.SelectNodes("//input");
                for (int nodeInput = 0; nodeCollectionInput != null && nodeInput < nodeCollectionInput.Count; nodeInput++)
                {
                    HtmlNode input = nodeCollectionInput[nodeInput];
                    // HtmlInputControl input = (HtmlInputControl)input.FindControl("input");
                    inputId = (input.Attributes["id"] != null) ? input.Attributes["id"].Value : "";
                    inputName = (input.Attributes["name"] != null) ? input.Attributes["name"].Value : "";
                    inputValue = (input.Attributes["value"] != null) ? input.Attributes["value"].Value : "";
                    inputType = (input.Attributes["type"] != null) ? input.Attributes["type"].Value : "";

                    InputDataStore newarr = new InputDataStore(inputId, inputName, formId, formName, inputValue, inputType, formNum);
                    arrayOfInputFields.Add(newarr);
                }
                formNum++;
            }
            #endregion

            //Begin testing each of the forms
            for (int i = 0; i < arrayOfForms.Count; i++)
            {
                string currentFormId = arrayOfForms[i].getId;
                string currentFormName = arrayOfForms[i].getName;
                string currentFormMethod = arrayOfForms[i].getMethod;
                string currentFormAction = arrayOfForms[i].getAction;
                int currentFormNum = arrayOfForms[i].getFormNum;

                List<InputDataStore> arrayOfCurrentFormsInputs = new List<InputDataStore>();

                for (int j = 0; j < arrayOfInputFields.Count; j++)
                {
                    string currentInputIdOfForm = arrayOfInputFields[j].getIdOfForm;
                    string currentInputNameOfForm = arrayOfInputFields[j].getNameOfForm;
                    int currentInputFormNum = arrayOfInputFields[j].getFormNum;

                    //Check if the current input field belongs to the current form and add to array if it does
                    if (currentFormNum == currentInputFormNum)
                    {
                        arrayOfCurrentFormsInputs.Add(arrayOfInputFields[j]);
                    }
                }

                for (int k = 0; k < arrayOfCurrentFormsInputs.Count; k++)
                {
                    for (int plIndex = 0; plIndex < payloads.Length; plIndex++)//foreach(string currentPayload in arrayOfAuthenticationPayloads)
                    {
                        string testStr = payloads[plIndex];
			            string defaultStr = "Abc123";
			            string indicatorStr = harmfulResponses[plIndex];
			
                        string currentFormInputName = arrayOfCurrentFormsInputs[k].getName;
                        string currentFormInputType = arrayOfCurrentFormsInputs[k].getType;
                        string currentFormInputValue = arrayOfCurrentFormsInputs[k].getValue;

                        if (currentFormInputType != "reset")
                        {
                            List<PostOrGetObject> arrayOfValues = new List<PostOrGetObject>();//Array of PostOrGetObject objects
                            List<InputDataStore> otherInputs = new List<InputDataStore>(); //Get the other input values and set them equal to the default string

                            for (int l = 0; l < arrayOfCurrentFormsInputs.Count; l++)
                            {
                                if (currentFormInputName != arrayOfCurrentFormsInputs[l].getName)
                                {
                                    otherInputs.Add(arrayOfCurrentFormsInputs[l]);
                                }
                            }

                            PostOrGetObject postObject = new PostOrGetObject(currentFormInputName, payloads[plIndex]);
                            //Add current input and other to array of post values and set their values
                            arrayOfValues.Add(postObject);

                            for (int m = 0; m < otherInputs.Count; m++)
                            {
                                string currentOtherType = otherInputs[m].getType;
                                string currentOtherName = otherInputs[m].getName;
                                string currentOtherValue = otherInputs[m].getValue;

                                if (currentOtherType == "text" || currentOtherType == "password")
                                {
                                    PostOrGetObject postObject1 = new PostOrGetObject(currentOtherName, defaultStr);
                                    arrayOfValues.Add(postObject1);
                                }
                                else if (currentOtherType == "checkbox" || currentOtherType == "submit")
                                {
                                    PostOrGetObject postObject1 = new PostOrGetObject(currentOtherName, currentOtherValue);
                                    arrayOfValues.Add(postObject1);
                                }
                                else if (currentOtherType == "radio")
                                {
                                    PostOrGetObject postObject1 = new PostOrGetObject(currentOtherName, currentOtherValue);
                                    //Check if a radio button in the radio group has already been added
                                    bool found = false;
                                    for (int n = 0; n < arrayOfValues.Count; n++)
                                    {
                                        if (arrayOfValues[n].gpName == postObject.gpName)
                                        {
                                            found = true;
                                            break;
                                        }
                                    }
                                    if (!found)
                                        arrayOfValues.Add(postObject1);
                                }
                            }

                            if (currentFormMethod == "get")
                            {
                                //Build query string and submit it at end of URL
                                if (!currentFormAction.Contains(urlOfSite))
                                {
                                    if (urlOfSite[urlOfSite.Length - 1] == '/')
                                        actionUrl = urlOfSite + currentFormAction;
                                    else
                                        actionUrl = urlOfSite + "/" + currentFormAction;
                                }
                                else
                                {
                                    actionUrl = currentFormAction;
                                }

                                totalTestStr = "";//Compile a test string to show the user how the vulnerability was tested for
                                for (int p = 0; p < arrayOfValues.Count; p++)
                                {
                                    string currentPostValueName = arrayOfValues[p].gpName;
                                    string currentPostValueValue = arrayOfValues[p].gpValue;

                                    totalTestStr += currentPostValueName;
                                    totalTestStr += '=';
                                    totalTestStr += currentPostValueValue;

                                    if (p != (arrayOfValues.Count - 1))
                                        totalTestStr += '&';
                                }
                                actionUrl += '?';
                                actionUrl += totalTestStr;

                                HttpWebRequest myHttpWebRequest = (HttpWebRequest)WebRequest.Create(actionUrl);
                                HttpWebResponse myHttpWebResponse = (HttpWebResponse)myHttpWebRequest.GetResponse();
                                Stream receiveStream = myHttpWebResponse.GetResponseStream();
                                StreamReader reader = new StreamReader(receiveStream, Encoding.UTF8);
                                String body = reader.ReadToEnd();

                                if (body.Length > 0)
                                {
                                    if (body.IndexOf(indicatorStr) != -1)
                                    {
                                        totalTestStr = "";//Make a test string to show the user how the vulnerability was tested for
                                        for (int p = 0; p < arrayOfValues.Count; p++)
                                        {
                                            string currentPostValueName = arrayOfValues[p].gpName;
                                            string currentPostValueValue = arrayOfValues[p].gpValue;

                                            totalTestStr += currentPostValueName;
                                            totalTestStr += '=';
                                            totalTestStr += currentPostValueValue;

                                            if (p != (arrayOfValues.Count - 1))
                                                totalTestStr += '&';
                                        }

                                        StringBuilder str = new StringBuilder();
                                        str.Append("<br>" + "Reflected XSS Present!" + "<br>" + "Query:" + urlToCheck + "<br>");
                                        str.Append("Method: GET <br>");
                                        str.Append("Url: " + totalTestStr + "<br>");
                                        str.Append("Error: " + indicatorStr + "<br>");
                                        result = str.ToString();
                                        Thread.Sleep(100);
                                        array.Add(str.ToString());
                                        myHttpWebResponse.Close();

                                        return;
                                    }
                                }
                                myHttpWebResponse.Close();
                            }
                            else if (currentFormMethod == "post")//Send data in body of request
                            {
                                //Build query string and submit it at end of URL
                                if (!currentFormAction.Contains(urlOfSite))
                                {
                                    if (urlOfSite[urlOfSite.Length - 1] == '/')
                                        actionUrl = urlOfSite + currentFormAction;
                                    else
                                        actionUrl = urlOfSite + "/" + currentFormAction;
                                }
                                else
                                {
                                    actionUrl = currentFormAction;
                                }


                                totalTestStr = "";//Compile a test string to show the user how the vulnerability was tested for
                                for (int p = 0; p < arrayOfValues.Count; p++)
                                {
                                    string currentPostValueName = arrayOfValues[p].gpName;
                                    string currentPostValueValue = arrayOfValues[p].gpValue;

                                    totalTestStr += currentPostValueName;
                                    totalTestStr += '=';
                                    totalTestStr += currentPostValueValue;

                                    if (p != (arrayOfValues.Count - 1))
                                        totalTestStr += '&';
                                }

                                //create the constructor with post type and few data
                                MyWebRequest myRequest = new MyWebRequest(actionUrl, "POST", totalTestStr);
                                //show the response string on the console screen.
                                String body = myRequest.GetResponse();

                                if (body.Length > 0)
                                {
                                    if (body.IndexOf(indicatorStr) != -1)
                                    {
                                        totalTestStr = "";//Make a test string to show the user how the vulnerability was tested for
                                        for (int p = 0; p < arrayOfValues.Count; p++)
                                        {
                                            string currentPostValueName = arrayOfValues[p].gpName;
                                            string currentPostValueValue = arrayOfValues[p].gpValue;

                                            totalTestStr += currentPostValueName;
                                            totalTestStr += '=';
                                            totalTestStr += currentPostValueValue;

                                            if (p != (arrayOfValues.Count - 1))
                                                totalTestStr += '&';
                                        }

                                        StringBuilder str = new StringBuilder();
                                        str.Append("<br>" + "Reflected XSS Present!" + "<br>" + "Query:" + urlToCheck + "<br>");
                                        str.Append("Method: GET <br>");
                                        str.Append("Url: " + totalTestStr + "<br>");
                                        str.Append("Error: " + indicatorStr + "<br>");
                                        result = str.ToString();
                                        Thread.Sleep(100);
                                        array.Add(str.ToString());
                                        //myHttpWebResponse.Close();

                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }*/
        }
    }
}