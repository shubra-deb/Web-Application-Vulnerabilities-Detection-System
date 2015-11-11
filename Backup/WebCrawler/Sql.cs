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
    public class Sql
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

            public MyWebRequest(string url, string method) : this(url)
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

            public MyWebRequest(string url, string method, string data) : this(url, method)
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

        //Defintion of all payloads used and warnings to examine for
        static string[] arrayOfPayloads = { "'",
						             "\"",
						             ";",
						             ")",
						             "(",
						             ".",
						             "--"
                                   };  //specified in webfuzz library (lib.webfuzz.js) from WebSecurify

        //From lib.webfuzz, some added by myself
        //The function checks for these errors after a payload is submitted
        static string[] arrayOfSQLWarnings = {		
                                        "supplied argument is not a valid MySQL", //MySQL
		                                "mysql_fetch_array\\(\\)",
		                                "on MySQL result index",
		                                "You have an error in your SQL syntax;",
		                                "You have an error in your SQL syntax near",
		                                "MySQL server version for the right syntax to use",
		                                "\\[MySQL\\]\\[ODBC",
		                                "Column count doesn't match",
		                                "the used select statements have different number of columns",
		                                "Table '[^']+' doesn't exist",
		                                "DB Error: unknown error",
		                                @":[\s]*mysql",
		                                "mysql_fetch",
                                        "Can't connect to local MySQL server",
		                                "System\\.Data\\.OleDb\\.OleDbException", //MS SQL
		                                "\\[SQL Server\\]",
		                                "\\[Microsoft\\]\\[ODBC SQL Server Driver\\]",
		                                "\\[SQLServer JDBC Driver\\]",
		                                "\\[SqlException",
		                                "System.Data.SqlClient.SqlException",
		                                "Unclosed quotation mark after the character string",
		                                "'80040e14'",
		                                "mssql_query\\(\\)",
		                                "odbc_exec\\(\\)",
		                                "Microsoft OLE DB Provider for ODBC Drivers",
		                                "Microsoft OLE DB Provider for SQL Server",
		                                "Incorrect syntax near",
		                                "Syntax error in string in query expression",
		                                "ADODB\\.Field \\(0x800A0BCD\\)<br>",
		                                "Procedure '[^']+' requires parameter '[^']+'",
		                                "ADODB\\.Recordset'",
		                                "Microsoft SQL Native Client error",
		                                "Unclosed quotation mark after the character string", 
		                                "SQLCODE", //DB2"
		                                "DB2 SQL error:",
		                                "SQLSTATE",
		                                "Sybase message:", //Sybase
		                                "Syntax error in query expression", //Access
		                                "Data type mismatch in criteria expression.",
		                                "Microsoft JET Database Engine",
		                                "\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]",
		                                "(PLS|ORA)-[0-9][0-9][0-9][0-9]", //Oracle
		                                "PostgreSQL query failed:", //PostGre
		                                "supplied argument is not a valid PostgreSQL result",
		                                "pg_query\\(\\) \\[:",
		                                "pg_exec\\(\\) \\[:",
		                                "com\\.informix\\.jdbc", //Informix
		                                "Dynamic Page Generation Error:",
		                                "Dynamic SQL Error",
		                                "\\[DM_QUERY_E_SYNTAX\\]", //DML
		                                "has occurred in the vicinity of:",
		                                "A Parser Error \\(syntax error\\)",
		                                "java\\.sql\\.SQLException",//Java
		                                "\\[Macromedia\\]\\[SQLServer JDBC Driver\\]" //Coldfusion	
            };//Defintion of all payloads used and warnings to examine for

        //Defintion of all payloads used and warnings to examine for
        //Payloads can be added to this
        static string[] arrayOfAuthenticationPayloads = {"'OR''='",
                                                         "1'or'1'='1';#",
                                                         "' or 1=1--",
                                                         "' or 0=0 --",
                                                         "' or 0=0 # ",
                                                        };

        //Variables
        static String body;
        private static bool vulnerabilityFound;
        public static string formId, formName, formMethod, formAction;
        public static string inputId, inputName, inputValue, inputType;
        static string totalTestStr;

        //Funcation
        static int numFound = 0;
        public static void DetectSql(string urlToCheck, ref string result, ref List<string> array)
        {
            //array = new List<string>();
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

                foreach (string currentPayload in arrayOfPayloads)
                {
                    foreach (string x in Parms.AllKeys)
                    {
                        query = originalQuery;
                        string newQuery = query.Replace(Parms[x], currentPayload);

                        query = newQuery;

                        string testUrl = scheme + "://" + host + path + '?' + query;

                        //MessageBox.Show("URL to be requested is: ",testUrl);
                        result = string.Format("URL to be requested is: " + testUrl);
                        Thread.Sleep(1000);

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
                                vulnerabilityFound = false;
                                string regularExpression = "";
                                for (int warningIndex = 0; warningIndex < arrayOfSQLWarnings.Length; warningIndex++)
                                {
                                    regularExpression = arrayOfSQLWarnings[warningIndex];

                                    if (body.Contains(regularExpression))//if (Regex.IsMatch(regularExpression, body))
                                    {
                                        //MessageBox.Show("Found regular expression: $regularExpression, in body of HTTP response");
                                        vulnerabilityFound = true;
                                        break;
                                    }
                                }
                                //showExtractConetent.InnerHtml += "<h1 class=bold>Links of Pages</h1>";
                                //Vulnerability details 
                                if (vulnerabilityFound)
                                {
                                    numFound++;
                                    StringBuilder str = new StringBuilder();
                                    str.Append("<br><span style='font-size:medium;font-weight: bold;color:red;'>" + numFound.ToString() + " Found SQL Injection Present!" + "</span><br>" + "Query:" + urlToCheck + "<br>");
                                    str.Append("Method: GET <br>");
                                    str.Append("Url: " + testUrl + "<br>");
                                    str.Append("Error: " + regularExpression + "<br>");
                                    result = str.ToString();            
                                    array.Add(urlToCheck);
                                    Thread.Sleep(1000);
                                  
                                    /*
                                    showExtractConetent.InnerHtml = "<br>SQL Injection Present!<br>Query:" + urlToCheck + "<br>";
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
                }
            }
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
                    for (int plIndex = 0; plIndex < arrayOfPayloads.Length; plIndex++)//foreach(string currentPayload in arrayOfAuthenticationPayloads)
                    {
                        string currentFormInputName = arrayOfCurrentFormsInputs[k].getName;
                        string currentFormInputType = arrayOfCurrentFormsInputs[k].getType;
                        string currentFormInputValue = arrayOfCurrentFormsInputs[k].getValue;

                        if (currentFormInputType != "reset")
                        {
                            string defaultStr = "Abc123";

                            List<PostOrGetObject> arrayOfValues = new List<PostOrGetObject>();
                            List<InputDataStore> otherInputs = new List<InputDataStore>();

                            for (int l = 0; l < arrayOfCurrentFormsInputs.Count; l++)
                            {
                                if (currentFormInputName != arrayOfCurrentFormsInputs[l].getName)
                                {
                                    otherInputs.Add(arrayOfCurrentFormsInputs[l]);
                                }
                            }

                            PostOrGetObject postObject = new PostOrGetObject(currentFormInputName, arrayOfPayloads[plIndex]);
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
                                    vulnerabilityFound = false;
                                    string regularExpression = "";
                                    for (int warningIndex = 0; warningIndex < arrayOfSQLWarnings.Length; warningIndex++)
                                    {
                                        regularExpression = arrayOfSQLWarnings[warningIndex];

                                        if (body.Contains(regularExpression))//if (Regex.IsMatch(regularExpression, body))
                                        {
                                            //MessageBox.Show("Found regular expression: $regularExpression, in body of HTTP response");
                                            vulnerabilityFound = true;
                                            break;
                                        }
                                    }
                                    //Vulnerability details 
                                    if (vulnerabilityFound)
                                    {
                                        StringBuilder str = new StringBuilder();
                                        str.Append("<br><span style='font-size:medium;font-style: bold;color:red;'>" + "SQL Injection Present!" +"</span><br>"+ "Query:" + urlToCheck + "<br>");
                                        result = str.ToString();
                                        array.Add(str.ToString());

                                        Thread.Sleep(1000);
                                        /*
                                        showExtractConetent.InnerHtml = "<br>SQL Injection Present!<br>Query:" + urlToCheck + "<br>";
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
                                    vulnerabilityFound = false;
                                    string regularExpression = "";
                                    for (int warningIndex = 0; warningIndex < arrayOfSQLWarnings.Length; warningIndex++)
                                    {
                                        regularExpression = arrayOfSQLWarnings[warningIndex];

                                        if (body.Contains(regularExpression))//if (Regex.IsMatch(regularExpression, body))
                                        {
                                            //MessageBox.Show("Found regular expression: $regularExpression, in body of HTTP response");
                                            vulnerabilityFound = true;
                                            break;
                                        }
                                    }
                                    //Vulnerability details 
                                    if (vulnerabilityFound)
                                    {
                                        StringBuilder str = new StringBuilder();
                                        str.Append("<br><span style='font-size:medium;font-style: bold;color:red;'>" + "SQL Injection Present!" + "</span><br>" + "Query:" + urlToCheck + "<br>");
                                        result = str.ToString();
                                        array.Add(str.ToString());

                                        Thread.Sleep(1000);
                                        /*
                                        showExtractConetent.InnerHtml = "<br>SQL Injection Present!<br>Query:" + urlToCheck + "<br>";
                                        showExtractConetent.InnerHtml = "Method: GET <br>";
                                        showExtractConetent.InnerHtml = "Url: " + testUrl + "<br>";
                                        showExtractConetent.InnerHtml = "Error: " + regularExpression + "<br>";
                                        */
                                        //myHttpWebResponse.Close();

                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public static void AuthenticationSql(string urlToCheck, ref string result, ref List<string> array)
        {
            string actionUrl;
            result = "By Pass Authentication SQL Injection started!!";
            var uri = new Uri(urlToCheck); // Find the length of the hostname
            //string urlOfSite = uri.Scheme + "://www." + uri.Host;
            string urlOfSite = uri.Host;

            //Load the html document from the url
            var webGet = new HtmlWeb();
            HtmlNode.ElementsFlags.Remove("form");
            HtmlDocument document = webGet.Load(urlToCheck);

            //Array containing all form objects found
            List<FormDataStore> arrayOfForms = new List<FormDataStore>();
            //Array containing all input fields
            List<InputDataStore> arrayOfInputFields = new List<InputDataStore>();

            //$log->lwrite("Searching $postUrl for forms");
            result = "Searching " + urlToCheck + " for forms...." ;
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

            //At this stage, we should have captured all forms and their input fields into the appropriate arrays

            //Begin testing each of the forms
            //Check if the URL passed into this function displays the same webpage at different intervals
            //If it does then attempt to login and if this URL displays a different page, the vulnerability is present
            //e.g. a login page would always look different when you are and are not logged in

            //*$log->lwrite("Checking if $urlToCheck displays the same page at different intervals");

            List<String> responseBodies = new List<String>(); //$responseBodies = array();

            for (int a = 0; a < 3; a++)
            {
                // Creates an HttpWebRequest for the specified URL. 
                HttpWebRequest myHttpWebRequest = (HttpWebRequest)WebRequest.Create(urlToCheck);
                // Sends the HttpWebRequest and waits for a response.
                HttpWebResponse myHttpWebResponse = (HttpWebResponse)myHttpWebRequest.GetResponse();

                Stream receiveStream = myHttpWebResponse.GetResponseStream();
                StreamReader reader = new StreamReader(receiveStream, Encoding.UTF8);
                String body = reader.ReadToEnd();
                if (body.Length > 0)
                {
                    responseBodies.Add(body);
                }
                myHttpWebResponse.Close();
            }
            bool pageChanges = true;
            string bodyOfUrl = "";
            if ((responseBodies[0] == responseBodies[1]) && (responseBodies[1] == responseBodies[2]))
            {
                bodyOfUrl = responseBodies[0];
                pageChanges = false;
            }

            //Begin testing each of the forms
            //$log->lwrite("Beginning testing of forms");
            for (int i = 0; i < arrayOfForms.Count; i++)
            {
                //$currentForm = arrayOfForms[i];
                string currentFormId = arrayOfForms[i].getId;
                string currentFormName = arrayOfForms[i].getName;
                string currentFormMethod = arrayOfForms[i].getMethod;
                string currentFormAction = arrayOfForms[i].getAction;
                int currentFormNum = arrayOfForms[i].getFormNum;

                //$arrayOfCurrentFormsInputs = array();

                List<InputDataStore> arrayOfCurrentFormsInputs = new List<InputDataStore>();

                result = "Beginning test of form....";

                //$log->lwrite("Beginning testing of form on $postUrl: $currentFormId $currentFormName $currentFormMethod $currentFormAction");
                //echo sizeof($arrayOfInputFields) . "<br>";
                for (int j = 0; j < arrayOfInputFields.Count; j++)
                {
                    //$currentInput = arrayOfInputFields[j];
                    string currentInputIdOfForm = arrayOfInputFields[j].getIdOfForm;
                    string currentInputNameOfForm = arrayOfInputFields[j].getNameOfForm;
                    int currentInputFormNum = arrayOfInputFields[j].getFormNum;

                    //Check if the current input field belongs to the current form and add to array if it does
                    if (currentFormNum == currentInputFormNum)
                    {
                        arrayOfCurrentFormsInputs.Add(arrayOfInputFields[j]);
                    }
                }

                //$log->lwrite("Beginning testing input fields of form on $postUrl: $currentFormId $currentFormName $currentFormMethod $currentFormAction");	

                foreach (string currentPayload in arrayOfAuthenticationPayloads)
                {
                    //echo sizeof($arrayOfCurrentFormsInputs) . '<br>';
                    List<PostOrGetObject> arrayOfValues = new List<PostOrGetObject>();

                    for (int k = 0; k < arrayOfCurrentFormsInputs.Count; k++)
                    {
                        //$currentFormInput = $arrayOfCurrentFormsInputs[k];
                        string currentFormInputName = arrayOfCurrentFormsInputs[k].getName;
                        string currentFormInputType = arrayOfCurrentFormsInputs[k].getType;
                        string currentFormInputValue = arrayOfCurrentFormsInputs[k].getValue;

                        if (currentFormInputType != "reset")
                        {
                            //$log->lwrite("Using payload: $currentPayload, to all input fields of form w/ action: $currentFormAction");
                            //Add current input and other inputs to array of post values and set their values
                            if (currentFormInputType == "text" || currentFormInputType == "password")
                            {
                                PostOrGetObject postObject = new PostOrGetObject(currentFormInputName, currentPayload);
                                arrayOfValues.Add(postObject);
                            }
                            else if (currentFormInputType == "checkbox" || currentFormInputType == "submit")
                            {
                                PostOrGetObject postObject = new PostOrGetObject(currentFormInputName, currentFormInputValue);
                                arrayOfValues.Add(postObject);
                            }
                            else if (currentFormInputType == "radio")
                            {
                                PostOrGetObject postObject = new PostOrGetObject(currentFormInputName, currentFormInputValue);

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
                                    arrayOfValues.Add(postObject);//array_push($arrayOfValues, $postObject);
                            }
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

                        // Creates an HttpWebRequest for the specified URL. 
                        HttpWebRequest myHttpWebRequest = (HttpWebRequest)WebRequest.Create(actionUrl);
                        // Sends the HttpWebRequest and waits for a response.
                        HttpWebResponse myHttpWebResponse = (HttpWebResponse)myHttpWebRequest.GetResponse();

                        Stream receiveStream = myHttpWebResponse.GetResponseStream();
                        StreamReader reader = new StreamReader(receiveStream, Encoding.UTF8);
                        String body = reader.ReadToEnd();
                        if (body.Length > 0)
                        {
                            myHttpWebResponse.Close();
                            vulnerabilityFound = checkIfVulnerabilityFound(urlToCheck, pageChanges, bodyOfUrl, currentPayload);
                            if (vulnerabilityFound)
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
                                numFound++;
                                StringBuilder str = new StringBuilder();
                                str.Append("<br><span style='font-size:medium;font-style: bold;color:red;'>" + numFound.ToString() + " Found Broken Authentication SQL Injection Present!" + "</span><br>" + "Query:" + urlToCheck + "<br>");
                                str.Append("Method: GET <br>");
                                str.Append("Url: " + totalTestStr + "<br>");
                                str.Append("Error:"+currentPayload+"<br>");
                                result = str.ToString();
                                array.Add(urlToCheck);
                                Thread.Sleep(1000);
                                break;

                            }
                        }
                        //myHttpWebResponse.Close();
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
                            //myHttpWebResponse.Close();
                            vulnerabilityFound = checkIfVulnerabilityFound(urlToCheck, pageChanges, bodyOfUrl, currentPayload);
                            if (vulnerabilityFound)
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
                                numFound++;
                                StringBuilder str = new StringBuilder();
                                str.Append("<br><span style='font-size:medium;font-style: bold;color:red;'>" + numFound.ToString() + " Found Broken Authentication SQL Injection Present!" + "</span><br>" + "Query:" + urlToCheck + "<br>");
                                str.Append("Method: POST <br>");
                                str.Append("Url: " + totalTestStr + "<br>");
                                str.Append("Error:" + currentPayload + "<br>");
                                result = str.ToString();
                                array.Add(urlToCheck);
                                Thread.Sleep(1000);
                                break;
                            }
                        }
                    }
                }
            }
        }

        public static bool checkIfVulnerabilityFound(string urlToCheck,bool pageChanges, string bodyOfUrl, string currentPayload)
        {
            string newBodyOfUrl = "";
            // Creates an HttpWebRequest for the specified URL. 
            HttpWebRequest myHttpWebRequest = (HttpWebRequest)WebRequest.Create(urlToCheck);
            // Sends the HttpWebRequest and waits for a response.
            HttpWebResponse myHttpWebResponse = (HttpWebResponse)myHttpWebRequest.GetResponse();

            Stream receiveStream = myHttpWebResponse.GetResponseStream();
            StreamReader reader = new StreamReader(receiveStream, Encoding.UTF8);
            String body = reader.ReadToEnd();
            if (body.Length > 0)
            {
                newBodyOfUrl = body;
            }
            myHttpWebResponse.Close();
            if (!pageChanges)//The page displayed from this URL does not change, so check if it is changed now after login attempt
            {
                if (bodyOfUrl != newBodyOfUrl)
                {
                    // Found broken authentication vulnerability
                    return true;
                }
                else
                {
                    //Body of URL is not different than before login attempt
                }
            }
            else //if the page displayed by the URL being tested does change at different levels, a different method must be used to identify if login was successful
            {
                //if the payload was not contained in the page, such as the login page, before but now it is, e.g. Hello 1'or'1'='1', authentication has been bypassed
                if ((bodyOfUrl.IndexOf(currentPayload) == -1) && (newBodyOfUrl.IndexOf(currentPayload) != -1))
                {
                    //Found broken authentication vulnerability
                    return true;
                }
                else
                {
                    bool LoggedIn = false;
                    string[] loggedInStrings = {"Hello",
									             "Welcome",
									             "Sign out",
									             "Signout",
									             "Log out",
									             "Logout",
									             "logged In"};

                    foreach (string currentStr in loggedInStrings)
                    {
                        if ((bodyOfUrl.IndexOf(currentStr) == -1) && (newBodyOfUrl.IndexOf(currentStr) != -1))
                        {
                            //Found broken authentication vulnerability
                            return true;
                        }
                    }

                }
            }
            return false;
        }

    }
}