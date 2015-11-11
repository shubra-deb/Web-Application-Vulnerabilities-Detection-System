﻿/****************************** Module Header ******************************\
* Module Name:    BackgroundWorker.cs
* Project:        CSASPNETBackgroundWorker
* Copyright (c) Microsoft Corporation
*
* The BackgroundWorker class calls a method in a separate thread. It allows 
* passing parameters to the method when it is called. And it can let the target 
* method report progress and result.
* 
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/opensource/licenses.mspx#Ms-PL.
* All other rights reserved.
*
\*****************************************************************************/

using System.Threading;
using System.Collections.Generic;

namespace WebCrawler
{
    /// <summary>
    /// This class is used to execute an operation in a separate thread.
    /// </summary>
    public class BackgroundWorker
    {
        /// <summary>
        /// This thread is used to run the operation in the background.
        /// </summary>
        Thread _innerThread = null;

        #region Properties
        /// <summary>
        /// A integer that shows the current progress.
        /// 100 value means the operation is completed.
        /// </summary>
        public int Progress 
        {
            set 
            {
                _progress = value;
            }
            get 
            {
                return _progress;
            }
        }
        int _progress = 0;

        /// <summary>
        /// A object that you can use it to save the result of the operation.
        /// </summary>
        public string  Result
        {
            set 
            {
                _result = value;
            }
            get
            {
                return _result;
            }
        }
        string _result = string.Empty;


        public List<string> array
        {
            get
            {
                return _array;
            }
        }
        List<string> _array = null;

        /// <summary>
        /// A boolean variable identifies if current Background Worker is
        /// working or not.
        /// </summary>
        public bool IsRunning
        {
            get
            {
                if (_innerThread != null)
                {
                    return _innerThread.IsAlive;
                }
                return false;
            }
        }

        public void Abort()
        {
            if (_innerThread != null)
            {
                _innerThread.Abort();
                _innerThread = null;
            }
        }
        #endregion

        #region Events
        /// <summary>
        /// 
        /// </summary>
        /// <param name="progress">
        /// Report the progress by changing its value
        /// </param>
        /// <param name="_result">
        /// Store value in this varialbe as the result
        /// </param>
        /// <param name="arguments">
        /// The parameters which will be passed to operation method
        /// </param>
        public delegate void DoWorkEventHandler(ref int progress,
            ref string _result, ref List<string> array,params object[] args);

        public event DoWorkEventHandler DoWork;
        #endregion

        /// <summary>
        /// Starts execution of a background operation.
        /// </summary>
        /// <param name="arguments">
        /// The parameters which will be passed to operation method
        /// </param>
        public void RunWorker(params object[] args)
        {
            if (DoWork != null)
            {
                _innerThread = new Thread(() =>
                {
                    _progress = 0;
                    DoWork.Invoke(ref _progress, ref _result,ref _array,args);
                    _progress = 100;
                });
                _innerThread.Start();
            }
        }
    }
}