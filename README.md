# Summary

The project demonstrates the usage of the AES block cipher in [GCM mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode), which is supposed to prevent [Padding Oracle Attack](https://en.wikipedia.org/wiki/Padding_oracle_attack). Other modes that can do that are CCM and EAX.

Relies on [Microsoft.Security.Cryptography](https://www.nuget.org/packages/Security.Cryptography/) as .NET does not provide an implementation of AES that works in GCM, CCM or EAX modes out of the box in:
https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aescryptoserviceprovider?view=netframework-4.7.2

More info at: https://blogs.msdn.microsoft.com/shawnfa/2009/03/17/authenticated-symmetric-encryption-in-net/


On the other hand, .NET Core provides some improvemnts:
https://github.com/dotnet/corefx/blob/master/src/System.Security.Cryptography.Algorithms/src/System/Security/Cryptography/AesGcm.cs
