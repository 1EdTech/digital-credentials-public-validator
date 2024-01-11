# Public Validator for Open Badges

Public Validator for Open Badges is a webapp designed to verify the validity of Open Badges based on a variety of input sources and present a useful interface for accessing their properties and validation information. HTTP and APIs are provided.

Public Validator for Open Badges is released by [1EdTech](https://www.1edtech.org).

## What versions of Open Badges does this validator support?

This is primarily a validator for Open Badges 3.0. You can submit badges that were created under Open Badges 2.0 specification as well, but we recommend using [Open Badges Validator Core](https://github.com/1EdTech/openbadges-validator-core) if you plan to validate Open Badges 2.0 and lower.

## User Documentation

### Requirements

- Java installed (tested with Java 17)
- Maven installed (tested with Maven 3.8.6)

### Installation & Run

Navigate to main folder and run `mvn clean verify`. There's no need to install the packages in your repository.

Run the webapp by navigate to the `inspector-vc-web` folder and run `mvn spring-boot:run`

### Usage
Run the webapp in the module `inspector-vc-web` and open a browser into `http://localhost:8080`. Once in the main page, select which validator to run from the list and provide your artifact / uri to validate.

If you want to use the validator via API, point the browser to `http://localhost:8080/swagger-ui.html` for more documentation about the API.

### How do I fix errors with badges?

This tool is (unfortunately) not a repair tool, though if you are the issuer, you may find the error messages the validator reports essential in identifying the errors. Errors are typically fixed by modifying one or more of the objects that make up the badge.

### Support

If you run into problems after following the installation and running instructions above, or if you have other kinds of questions relating to the use of the tool and/or the interpretation of results, please use the [1EdTech Open Badges Community forum](https://www.imsglobal.org/forums/open-badges-community-forum/open-badges-community-discussion), the [Comprehensive Learner Record Public Forum](https://www.imsglobal.org/forums/ims-glc-public-forums-and-resources/comprehensive-learner-record-public-forum) to ask your questions (and/or help others).

## How to contribute

If you have found what might be a bug in the application, open an issue in the [issue tracker](https://github.com/1edtech/vc-public-validator/issues) with the label ‘bug’. The project owners will discuss the issue with you, and if it is indeed a bug, the issue will be confirmed and dealt with. (For general usage questions, please use the [1EdTech Open Badges Community forum](https://www.imsglobal.org/forums/open-badges-community-forum/open-badges-community-discussion) instead of the issue tracker. See the Support section in this document).

If you are a developer and want to contribute to the project, please begin with opening an issue in the tracker describing the change or addition you want to contribute. If we after discussing the matter can confirm the usefulness of your planned contribution, then get ready to contribute. We follow the [standard git flow for contributing to projects](https://git-scm.com/book/en/v2/GitHub-Contributing-to-a-Project), in other words, using pull requests from topic branches, followed by review by a project owner before merge.

Note that the open source license of this project will apply to your inbound contributions. Note also that under certain circumstances an 1EdTech contributor agreement will need to be filled in. (This is one of the main reasons we want you to talk to us in the issue tracker before you spend time on coding).

## Developer Documentation

This is a multi module maven project with two modules:

- `inspector-vc`: the validator for Open Badges 3.0.
- `inspector-vc-web`: the webapp which runs the validator and presents the results to the user.


### `inspector-vc-web`

Contains a Spring Boot-based app that exposes a REST API and a web UI. The web UI's
entry point is "/"; the REST API is documented at "/swagger-ui.html".

> This webapp is a specialization of a private, generic web application (`inspector-web-public`). This module only defines the validators to use

### `inspector-vc`

Constains the inspector implementations for:

- Open Badges 2.0: `org.oneedtech.inspect.vc.OB20Inspector`
- Open Badges 3.0: `org.oneedtech.inspect.vc.OB30Inspector`

These inspectors contains all the probes to perform to an artifact for validating its conformance to that specification, building a `Report` with the results.

The method `run` is the responsible to perform such probes.
