import { generateFileExplorerScript } from './clientScripts';
import { generateFileExplorerHTMLStructure } from './htmlStructure';

/**
 * Generate complete HTML for WebDAV file explorer
 * @param title - Page title
 * @param items - Initial file/folder items
 * @param currentPath - Current directory path (default: '/')
 * @returns Complete HTML document as string
 */
export function generateHTML(title: string, items: { name: string; href: string }[], currentPath = '/'): string {
	// The heavy UI logic runs on the client; we pass minimal initial data to avoid duplicate fetch.
	const initialItems = JSON.stringify(items || []);
	const scriptContent = generateFileExplorerScript(currentPath, initialItems);
	return generateFileExplorerHTMLStructure(title, scriptContent);
}
