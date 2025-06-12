/*
 * Get application proxy by bundle identifier
 * @param {string} bundleId bundle id of the app
 * @returns {ObjC.Object} application proxy object
 */
function getApp(bundleId) {
	// Get application proxy for the given bundle identifier.
	const app = ObjC.classes.LSApplicationProxy.applicationProxyForIdentifier_(bundleId)
	if (!app) {
		throw new Error(`bundle identifier "${bundleId}" not found`)
	}

	return app
}

/**
 * Get list of extensions for the host app
 * @param {string} bundleId bundle id of the app
 * @returns {ExtensionInfo[]} list of extensions
 */
rpc.exports.extensions = function (bundleId) {
	// Iterate through plugins to find extensions
	var extensions = []

	const plugins = getApp(bundleId).plugInKitPlugins()

	for (let i = 0; i < plugins.count(); i++) {
		const plugin = plugins.objectAtIndex_(i)
		const plist = plugin.infoPlist()

		const id = plugin.bundleIdentifier().toString()
		const path = plist.objectForKey_('Path').toString()
		const executable = plist.objectForKey_('CFBundleExecutable').toString()
		const absolutePath = path + '/' + exec

		extensions.push({ id, path, executable, absolutePath })
	}

	return extensions
}

/**
 * Get main executable of the app
 * @param {string} bundleId bundle id of the app
 * @returns {string} path to the main executable
 */
rpc.exports.main = function (bundleId) {
	return getApp(bundleId).bundleExecutable().toString()
}
