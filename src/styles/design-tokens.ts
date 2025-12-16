/**
 * R2 WebDAV Design System Tokens
 *
 * 设计令牌（Design Tokens）- 项目样式的单一真实来源
 *
 * 使用方式：
 * ```ts
 * import { COLORS, SPACING, TYPOGRAPHY } from '@/styles/design-tokens';
 *
 * const buttonClass = `${COLORS.button.primary} ${SPACING.padding.button}`;
 * ```
 */

// ========================================
// 色彩系统 (Color System)
// ========================================

export const COLORS = {
	// 灰度系统 - 项目主色调
	neutral: {
		50: 'gray-50', // #f9fafb - 浅色背景
		100: 'gray-100', // #f3f4f6 - 卡片背景（浅色模式）
		200: 'gray-200', // #e5e7eb - 分割线、边框
		300: 'gray-300', // #d1d5db - 次要边框
		400: 'gray-400', // #9ca3af - 占位符文字
		500: 'gray-500', // #6b7280 - 次要文字
		600: 'gray-600', // #4b5563 - 辅助文字
		700: 'gray-700', // #374151 - 主要文字（浅色模式）
		800: 'gray-800', // #1f2937 - 卡片背景（暗黑模式）
		900: 'gray-900', // #111827 - 背景（暗黑模式）/ 主按钮（浅色模式）
		950: 'gray-950', // #030712 - 深度背景（暗黑模式）
	},

	// 强调色 - 蓝色（仅用于交互状态）
	accent: {
		50: 'blue-50', // #eff6ff - 信息提示背景
		400: 'blue-400', // #60a5fa - focus 状态（暗黑模式）
		500: 'blue-500', // #3b82f6 - focus 状态（浅色模式）
		800: 'blue-800', // #1e40af - 信息提示边框（暗黑模式）
	},

	// 语义色
	semantic: {
		error: {
			50: 'red-50', // #fef2f2 - 错误提示背景
			400: 'red-400', // #f87171 - 错误文字（暗黑模式）
			600: 'red-600', // #dc2626 - 错误文字（浅色模式）
			800: 'red-800', // #991b1b - 错误边框（暗黑模式）
		},
		warning: {
			50: 'amber-50', // #fffbeb - 警告提示背景
			400: 'amber-400', // #fbbf24 - 警告图标
		},
	},

	// 组件专用色彩（预定义组合）
	button: {
		// 主按钮：深灰底白字（浅色）/ 白底深字（暗黑）
		primary: 'bg-gray-900 hover:bg-gray-800 dark:bg-white dark:hover:bg-gray-100 text-white dark:text-gray-900',
		// 次要按钮：灰色边框
		secondary:
			'border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800',
	},

	background: {
		// 页面背景
		page: 'bg-gray-100 dark:bg-gray-900',
		// 卡片背景
		card: 'bg-white dark:bg-gray-800',
		// Logo 背景
		icon: 'bg-gray-100 dark:bg-gray-700',
	},

	text: {
		// 主要文字
		primary: 'text-gray-900 dark:text-gray-100',
		// 次要文字
		secondary: 'text-gray-500 dark:text-gray-400',
		// 标签文字
		label: 'text-gray-700 dark:text-gray-300',
	},

	border: {
		// 标准边框
		default: 'border-gray-200 dark:border-gray-700',
		// 输入框边框
		input: 'border-gray-300 dark:border-gray-600',
		// focus 状态边框
		focus: 'border-blue-500 dark:border-blue-400',
	},
} as const;

// ========================================
// 间距系统 (Spacing System)
// ========================================

/**
 * 基于 4px 网格系统
 * Tailwind 默认: spacing = 0.25rem = 4px
 */
export const SPACING = {
	// 内边距（Padding）
	padding: {
		// 按钮内边距：py-3 = 12px
		button: 'py-3',
		// 输入框内边距：px-4 py-2.5 = 16px 10px
		input: 'px-4 py-2.5',
		// 卡片内边距：p-8 = 32px
		card: 'p-8',
		// 提示框内边距：p-3.5 = 14px
		alert: 'p-3.5',
	},

	// 外边距（Margin）- Material Design 风格（更宽松的间距）
	margin: {
		// label 和 input 之间：mb-2 = 8px
		labelInput: 'mb-2',
		// 表单元素之间：mb-5 = 20px
		formElement: 'mb-5',
		// 提交按钮上方：mb-8 = 32px
		submitButton: 'mb-8',
		// 分组间距：mb-10 = 40px
		section: 'mb-10',
	},

	// 间隙（Gap）
	gap: {
		// 图标和文字：gap-2 = 8px
		iconText: 'gap-2',
	},
} as const;

// ========================================
// 字体系统 (Typography System)
// ========================================

export const TYPOGRAPHY = {
	// 字号
	size: {
		// 12px - 辅助文字、标签
		xs: 'text-xs',
		// 14px - 次要文字、描述
		sm: 'text-sm',
		// 16px - 正文
		base: 'text-base',
		// 18px - 子标题、品牌名
		lg: 'text-lg',
		// 24px - 页面标题
		'2xl': 'text-2xl',
	},

	// 字重
	weight: {
		// 400 - 正文
		normal: 'font-normal',
		// 500 - 标签、按钮、强调文字
		medium: 'font-medium',
		// 600 - 子标题、卡片标题
		semibold: 'font-semibold',
	},

	// 预定义组合
	heading: {
		// 页面主标题：24px / 600
		page: 'text-2xl font-semibold',
		// 卡片标题：18px / 600
		card: 'text-lg font-semibold',
	},

	body: {
		// 正文：16px / 400
		default: 'text-base font-normal',
		// 次要说明：14px / 400
		secondary: 'text-sm font-normal',
	},

	label: {
		// 表单标签：14px / 500
		form: 'text-sm font-medium',
	},
} as const;

// ========================================
// 圆角系统 (Border Radius)
// ========================================

export const RADIUS = {
	// 8px - 按钮、输入框
	button: 'rounded-lg',
	// 8px - 输入框
	input: 'rounded-lg',
	// 8px - 提示框
	alert: 'rounded-lg',
	// 12px - Logo 背景
	icon: 'rounded-xl',
	// 16px - 卡片
	card: 'rounded-2xl',
} as const;

// ========================================
// 阴影系统 (Shadow System)
// ========================================

export const SHADOW = {
	// 柔和阴影 - 小元素
	sm: 'shadow-sm',
	// 中等阴影 - 卡片、对话框（Material Design 风格）
	md: 'shadow-md',
	// 按钮阴影
	button: 'shadow-sm hover:shadow-md',
	// 输入框内阴影 - 创造深度感
	inputInset: 'shadow-[inset_0_2px_4px_rgba(0,0,0,0.06)]',
	inputInsetDark: 'dark:shadow-[inset_0_2px_4px_rgba(0,0,0,0.2)]',
} as const;

// ========================================
// 动画系统 (Animation System)
// ========================================

export const ANIMATION = {
	// 过渡时长
	duration: {
		// 150ms - 标准交互（按钮、输入框）
		fast: 'duration-150',
		// 400ms - 淡入动画
		normal: 'duration-400',
	},

	// 缓动函数
	easing: {
		default: 'ease-out',
	},

	// 完整过渡类
	transition: 'transition duration-150',
} as const;

// ========================================
// 组件样式组合 (Component Presets)
// ========================================

/**
 * 预定义的组件样式组合
 * 直接使用可确保视觉一致性
 */
export const COMPONENTS = {
	// 主按钮
	buttonPrimary: [
		'w-full',
		SPACING.padding.button,
		COLORS.button.primary,
		RADIUS.button,
		'font-medium',
		SHADOW.button,
		ANIMATION.transition,
	].join(' '),

	// 次要按钮
	buttonSecondary: [
		'w-full',
		SPACING.padding.button,
		COLORS.button.secondary,
		RADIUS.button,
		'font-medium',
		SHADOW.button,
		ANIMATION.transition,
	].join(' '),

	// 输入框
	input: [
		'w-full',
		SPACING.padding.input,
		RADIUS.input,
		'border-2',
		COLORS.border.input,
		COLORS.background.card,
		COLORS.text.primary,
		SHADOW.inputInset,
		SHADOW.inputInsetDark,
		'focus:outline-none',
		COLORS.border.focus,
		'focus:ring-2',
		'focus:ring-blue-500',
		'dark:focus:ring-blue-400',
		ANIMATION.transition,
	].join(' '),

	// 表单标签
	label: [TYPOGRAPHY.label.form, COLORS.text.label, SPACING.margin.labelInput].join(' '),

	// 卡片容器
	card: [COLORS.background.card, RADIUS.card, SHADOW.md, SPACING.padding.card, 'border', COLORS.border.default].join(
		' ',
	),

	// 错误提示
	errorAlert: [
		SPACING.padding.alert,
		'bg-red-50 dark:bg-red-900/10',
		'border border-red-200 dark:border-red-800/50',
		RADIUS.alert,
		'text-sm',
		'text-red-600 dark:text-red-400',
	].join(' '),

	// 信息提示
	infoAlert: [
		SPACING.padding.alert,
		'bg-blue-50 dark:bg-blue-900/10',
		'border border-blue-200 dark:border-blue-800/50',
		RADIUS.alert,
		'text-sm',
		COLORS.text.label,
	].join(' '),
} as const;

// ========================================
// 导出所有 tokens
// ========================================

export const DESIGN_TOKENS = {
	COLORS,
	SPACING,
	TYPOGRAPHY,
	RADIUS,
	SHADOW,
	ANIMATION,
	COMPONENTS,
} as const;

export default DESIGN_TOKENS;
