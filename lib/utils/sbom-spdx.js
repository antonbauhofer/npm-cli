const spdx = require('spdx-tools')
const crypto = require('crypto')
const npa = require('npm-package-arg')

const NO_ASSERTION = 'NOASSERTION'

const REL_DESCRIBES = 'DESCRIBES'
const REL_PREREQ = 'HAS_PREREQUISITE'
const REL_OPTIONAL = 'OPTIONAL_DEPENDENCY_OF'
const REL_DEV = 'DEV_DEPENDENCY_OF'
const REL_DEP = 'DEPENDS_ON'

const spdxOutput = ({ npm, nodes, packageType }) => {
  const rootNode = nodes.find(node => node.isRoot)
  const rootID = rootNode.pkgid
  const uuid = crypto.randomUUID()
  const ns = `http://spdx.org/spdxdocs/${npa(rootID).escapedName}-${rootNode.version}-${uuid}`

  const spdxDocument = spdx.createDocument(
    rootID, { creators: { name: `npm/cli-${npm.version}`, type: 'Tool' },
      namespace: ns }
  )
  // const pkg = spdxDocument.addPackage('name', 'location')
  // spdxDocument.addRelationship(spdxDocument, pkg, REL_DESCRIBES)

  const seen = new Set()
  for (let node of nodes) {
    const nodeSpdxId = toSpdxID(node)
    if (node.isRoot) {
      spdxDocument.addRelationship(spdxDocument, nodeSpdxId, REL_DESCRIBES)
      spdxDocument.addPackage(node.packageName,
        (node.isLink ? undefined : node.resolved) || NO_ASSERTION, { spdxId: nodeSpdxId })
    } else if (!node.isRoot && !node.isLink) {
      spdxDocument.addPackage(node.packageName,
        (node.isLink ? undefined : node.resolved) || NO_ASSERTION, { spdxId: nodeSpdxId })
    }

    if (node.isLink) {
      node = node.target
    }

    if (seen.has(node)) {
      continue
    }
    seen.add(node);

    [...node.edgesOut.values()]
      .filter(edge => nodes.find(n => n === edge.to))
      .map(edge => spdxDocument
        .addRelationship(nodeSpdxId, toSpdxID(edge.to), getRelationshipType(edge)))
  }

  nodes.filter(node => node.extraneous)
    .map(node => spdxDocument.addRelationship(toSpdxID(rootNode), toSpdxID(node), REL_OPTIONAL))

  // console.log(spdxDocument)
  // TODO: Fix this. At the moment it just creates an empty file.
  spdxDocument.writeSync('sbom.spdx.json', true)
}

const getRelationshipType = (edge) => {
  switch (edge.type) {
    case 'peer':
      return REL_PREREQ
    case 'optional':
      return REL_OPTIONAL
    case 'dev':
      return REL_DEV
    default:
      return REL_DEP
  }
}

const toSpdxID = (node) => {
  let name = node.packageName

  // Strip leading @ for scoped packages
  name = name.replace(/^@/, '')

  // Replace slashes with dots
  name = name.replace(/\//g, '.')

  return `SPDXRef-Package-${name}-${node.version}`
}

module.exports = { spdxOutput }
