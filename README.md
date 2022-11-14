# U-Prove Node Reference Implementation

This project provides a Node reference implementation of the Lite profile of the [U-Prove Specification 1.1 (Revision 4)](./doc/U-Prove%20Cryptographic%20Specification%20V1.1%20Revision%204.pdf). The [U-Prove technology](https://microsoft.com/uprove) enables the creation of unlinkable credentials which can encode attributes of any types, supporting selective subset disclosure. The Lite profile of the specification simplifies the implementation by limiting the feature set; namely it _does not_ support:
* The subgroup construction
* Device binding
* Scope-exclusive pseudonyms
* Presenting committed attributes

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both.

1. Get the source, for example using `git`
```
git clone -b main https://github.com/microsoft/uprove-node-reference.git
cd uprove-node-reference
```

2. Build the `npm` package
```
npm install
npm run build
```

3. Optionally, run the unit tests

```
npm test
```

4. Optionally, run the sample program

```
npm run sample
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
