using System.Reflection;
// <copyright file="ReferenceTest.cs" company="AXF Software">Copyright ©  2016</copyright>

using System;
using AXFSoftware.Security.Cryptography.Turing.Tests;
using Microsoft.Pex.Framework;
using Microsoft.Pex.Framework.Validation;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AXFSoftware.Security.Cryptography.Turing.Tests.Tests
{
    [TestClass]
    [PexClass(typeof(Reference))]
    [PexAllowedExceptionFromTypeUnderTest(typeof(ArgumentException), AcceptExceptionSubtypes = true)]
    [PexAllowedExceptionFromTypeUnderTest(typeof(InvalidOperationException))]
    public partial class ReferenceTest
    {

        [PexMethod(MaxBranches = 20000)]
        [PexMethodUnderTest("DoesBasicEncryptionCorrectly()")]
        internal void DoesBasicEncryptionCorrectly([PexAssumeUnderTest]Reference target)
        {
            object[] args = new object[0];
            Type[] parameterTypes = new Type[0];
            object result = ((MethodBase)(typeof(Reference).GetMethod("DoesBasicEncryptionCorrectly",
                                                                      BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.NonPublic, (Binder)null,
                                                                      CallingConventions.HasThis, parameterTypes, (ParameterModifier[])null)))
                                .Invoke((object)target, args);
            // TODO: add assertions to method ReferenceTest.DoesBasicEncryptionCorrectly(Reference)
        }
    }
}
