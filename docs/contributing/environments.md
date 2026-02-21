# Environments
> [!WARNING]
> For end users, Slashstep Group only using the [production environment](#production). End users may encounter unexpected bugs in lower environments more frequently, which may degrade the experience. 

## Development
### Purpose of development environment
The `main` branch represents the development environment.

### Development environment security
* Only collaborators with write access can push to the development environment.
* All contributors must sign their commits prior to pushing to the `main` branch.
* All Rust tests, if applicable, must pass before pushing to the `main` branch.
* All contributors are required to use a pull request before pushing to the `main` branch.
* Non-maintainers must have their pull requests approved by a maintainer before pushing to the `main` branch.
* Force pushing is not allowed on the main branch.

### Development images
Whenever a contributor commits to the `main` branch, GitHub Actions creates a development image of Slashstep Server. This image is available at:
* `ghcr.io/slashstepgroup/slashstep-server:development`
* `ghcr.io/slashstepgroup/slashstep-server:main`

## Staging
### Purpose of staging environment
The staging environment is for quality assurance and user acceptance testing.

### Staging environment security
* All contributors without admin access must use GitHub Actions to deploy to the staging environment. Only collaborators with admin access can directly publish staging images; but, even then, admins should avoid deploying directly to preserve transparency.
* All staging deployments require approval from another collaborator with at least write access. Currently, due to a shortage of maintainers, the producer is exempt from this rule.

### Staging images
When a maintainer publishes a prerelease, then GitHub Actions creates a staging image of Slashstep Server. This image is available at:
* `ghcr.io/slashstepgroup/slashstep-server:staging`

## Production
### Purpose of production environment
The production environment is for end users. 

### Production environment security
* All contributors without admin access must use GitHub Actions to deploy to the production environment. Only collaborators with admin access can directly publish production images; but, even then, admins should avoid deploying directly to preserve transparency.
* All production deployments require approval from another collaborator with at least write access. Currently, due to a shortage of maintainers, the producer is exempt from this rule.

### Production images
> [!TIP]
> Slashstep Group recommends specifying the version-specific tags rather than relying on the named tags like "production" and "latest". This way, admins aren't surprised by unpredictable behavior.

When a maintainer publishes a release, then GitHub Actions creates a production image of Slashstep Server. 

<table>
  <thead>
    <tr>
      <th>Image</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>
        <code>ghcr.io/slashstepgroup/slashstep-server:{X.Y.Z}</code>, where <code>{X.Y.Z}</code> is the version of Slashstep Server that you want.
      </td>
      <td>
        If you want a fully predictable version of Slashstep Server, this is the recommended way of doing things. On the other hand, you will have to manually update Slashstep Server whenever a new version comes out that you want to use. Remember: security is not equal to convenience!
      </td>
    </tr>
    <tr>
      <td>
        <code>ghcr.io/slashstepgroup/slashstep-server:{X.Y}</code>, where <code>{X.Y}</code> is the version of Slashstep Server that you want.
      </td>
      <td>
        You will get the latest patch version with a constraint on the <code>X</code> major version and <code>Y</code> minor version. For example, if you're targeting <code>ghcr.io/slashstepgroup/slashstep-server:1.2</code> and the latest version is v1.2.3, then you will get Slashstep Server v1.2.3 when you pull and run the image.
        <br />
        <br />This is helpful if you just want automatic bug fixes for a particular minor version.
      </td>
    </tr>
    <tr>
      <td>
        <code>ghcr.io/slashstepgroup/slashstep-server:{X}</code>, where <code>{X}</code> is the version of Slashstep Server that you want.
      </td>
      <td>
        You will get the latest minor and patch versions with a constraint on the <code>X</code> major version. For example, if you're targeting <code>ghcr.io/slashstepgroup/slashstep-server:1</code> and the latest version is v1.2.3, then you will get Slashstep Server v1.2.3 when you pull and run the image.
        <br />
        <br />This is helpful if you want automatic feature implementations and bug fixes without unexpected feature removals or breaking changes.
      </td>
    </tr>
    <tr>
      <td>
        <code>ghcr.io/slashstepgroup/slashstep-server</code>
      </td>
      <td rowspan="3">
        You will get the latest major, minor, and patch versions. For example, if you're targeting <code>ghcr.io/slashstepgroup/slashstep-server</code> and the latest version is v3.2.1, then you will get Slashstep Server v3.2.1 when you pull and run the image.
        <br />
        <br />This is helpful if you want the always up-to-date version of Slashstep Server. Some breaking changes may need Slashstep Server admin assistance, so Slashstep Group recommends using the <code>ghcr.io/slashstepgroup/slashstep-server:{X}</code> tag instead to prevent potential downtime; but, if you want less back end server maintenance on your hands, these images are here as options.
      </td>
    </tr>
    <tr>
      <td>
        <code>ghcr.io/slashstepgroup/slashstep-server:production</code>
      </td>
    </tr>
    <tr>
      <td>
        <code>ghcr.io/slashstepgroup/slashstep-server:latest</code>
      </td>
    </tr>
  </tbody>
</table>