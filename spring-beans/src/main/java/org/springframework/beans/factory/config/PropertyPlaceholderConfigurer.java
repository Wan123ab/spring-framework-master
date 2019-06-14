/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.beans.factory.config;

import java.util.Properties;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.core.Constants;
import org.springframework.core.PriorityOrdered;
import org.springframework.core.SpringProperties;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.lang.Nullable;
import org.springframework.util.PropertyPlaceholderHelper;
import org.springframework.util.PropertyPlaceholderHelper.PlaceholderResolver;
import org.springframework.util.StringValueResolver;

/**
 * {@link PlaceholderConfigurerSupport} subclass that resolves ${...} placeholders against
 * {@link #setLocation local} {@link #setProperties properties} and/or system properties
 * and environment variables.
 *
 * <p>{@link PropertyPlaceholderConfigurer} is still appropriate for use when:
 * <ul>
 * <li>the {@code spring-context} module is not available (i.e., one is using Spring's
 * {@code BeanFactory} API as opposed to {@code ApplicationContext}).
 * <li>existing configuration makes use of the {@link #setSystemPropertiesMode(int) "systemPropertiesMode"}
 * and/or {@link #setSystemPropertiesModeName(String) "systemPropertiesModeName"} properties.
 * Users are encouraged to move away from using these settings, and rather configure property
 * source search order through the container's {@code Environment}; however, exact preservation
 * of functionality may be maintained by continuing to use {@code PropertyPlaceholderConfigurer}.
 * </ul>
 *
 * @author Juergen Hoeller
 * @author Chris Beams
 * @since 02.10.2003
 * @see #setSystemPropertiesModeName
 * @see PlaceholderConfigurerSupport
 * @see PropertyOverrideConfigurer
 * @deprecated as of 5.2; use {@code org.springframework.context.support.PropertySourcesPlaceholderConfigurer}
 * instead which is more flexible through taking advantage of the {@link org.springframework.core.env.Environment}
 * and {@link org.springframework.core.env.PropertySource} mechanisms.
 */

/**
 * BeanFactoryPostProcessor有2个非常重要的子类：
 * 1、PropertyPlaceholderConfigurer:允许我们通过配置 Properties 的方式来取代Bean中定义的占位符---可以处理任何bean的占位符
 * 2、PropertyOverrideConfigurer:允许我们对 Spring 容器中配置的任何bean定义的property信息进行覆盖替换---可以处理指定bean的指定属性
 *
 * PropertyPlaceholderConfigurer允许我们用Properties文件来配置XML文件（或者其他方式，如注解方式）中的占位符
 *
 * PropertyOverrideConfigurer实现接口
 * @see BeanFactoryPostProcessor
 * @see PriorityOrdered
 * @see BeanFactoryAware
 * @see BeanNameAware
 */
@Deprecated
public class PropertyPlaceholderConfigurer extends PlaceholderConfigurerSupport {

	/** Never check system properties. */
	public static final int SYSTEM_PROPERTIES_MODE_NEVER = 0;

	/**
	 * Check system properties if not resolvable in the specified properties.
	 * This is the default.
	 */
	public static final int SYSTEM_PROPERTIES_MODE_FALLBACK = 1;

	/**
	 * Check system properties first, before trying the specified properties.
	 * This allows system properties to override any other property source.
	 */
	public static final int SYSTEM_PROPERTIES_MODE_OVERRIDE = 2;


	private static final Constants constants = new Constants(PropertyPlaceholderConfigurer.class);

	private int systemPropertiesMode = SYSTEM_PROPERTIES_MODE_FALLBACK;

	private boolean searchSystemEnvironment =
			!SpringProperties.getFlag(AbstractEnvironment.IGNORE_GETENV_PROPERTY_NAME);


	/**
	 * Set the system property mode by the name of the corresponding constant,
	 * e.g. "SYSTEM_PROPERTIES_MODE_OVERRIDE".
	 * @param constantName name of the constant
	 * @see #setSystemPropertiesMode
	 */
	public void setSystemPropertiesModeName(String constantName) throws IllegalArgumentException {
		this.systemPropertiesMode = constants.asNumber(constantName).intValue();
	}

	/**
	 * Set how to check system properties: as fallback, as override, or never.
	 * For example, will resolve ${user.dir} to the "user.dir" system property.
	 * <p>The default is "fallback": If not being able to resolve a placeholder
	 * with the specified properties, a system property will be tried.
	 * "override" will check for a system property first, before trying the
	 * specified properties. "never" will not check system properties at all.
	 * @see #SYSTEM_PROPERTIES_MODE_NEVER
	 * @see #SYSTEM_PROPERTIES_MODE_FALLBACK
	 * @see #SYSTEM_PROPERTIES_MODE_OVERRIDE
	 * @see #setSystemPropertiesModeName
	 */
	public void setSystemPropertiesMode(int systemPropertiesMode) {
		this.systemPropertiesMode = systemPropertiesMode;
	}

	/**
	 * Set whether to search for a matching system environment variable
	 * if no matching system property has been found. Only applied when
	 * "systemPropertyMode" is active (i.e. "fallback" or "override"), right
	 * after checking JVM system properties.
	 * <p>Default is "true". Switch this setting off to never resolve placeholders
	 * against system environment variables. Note that it is generally recommended
	 * to pass external values in as JVM system properties: This can easily be
	 * achieved in a startup script, even for existing environment variables.
	 * @see #setSystemPropertiesMode
	 * @see System#getProperty(String)
	 * @see System#getenv(String)
	 */
	public void setSearchSystemEnvironment(boolean searchSystemEnvironment) {
		this.searchSystemEnvironment = searchSystemEnvironment;
	}

	/**
	 * Resolve the given placeholder using the given properties, performing
	 * a system properties check according to the given mode.
	 * <p>The default implementation delegates to {@code resolvePlaceholder
	 * (placeholder, props)} before/after the system properties check.
	 * <p>Subclasses can override this for custom resolution strategies,
	 * including customized points for the system properties check.
	 * @param placeholder the placeholder to resolve
	 * @param props the merged properties of this configurer
	 * @param systemPropertiesMode the system properties mode,
	 * according to the constants in this class
	 * @return the resolved value, of null if none
	 * @see #setSystemPropertiesMode
	 * @see System#getProperty
	 * @see #resolvePlaceholder(String, java.util.Properties)
	 */
	@Nullable
	protected String resolvePlaceholder(String placeholder, Properties props, int systemPropertiesMode) {
		String propVal = null;
		if (systemPropertiesMode == SYSTEM_PROPERTIES_MODE_OVERRIDE) {
			propVal = resolveSystemProperty(placeholder);
		}
		if (propVal == null) {
			propVal = resolvePlaceholder(placeholder, props);
		}
		if (propVal == null && systemPropertiesMode == SYSTEM_PROPERTIES_MODE_FALLBACK) {
			propVal = resolveSystemProperty(placeholder);
		}
		return propVal;
	}

	/**
	 * Resolve the given placeholder using the given properties.
	 * The default implementation simply checks for a corresponding property key.
	 * <p>Subclasses can override this for customized placeholder-to-key mappings
	 * or custom resolution strategies, possibly just using the given properties
	 * as fallback.
	 * <p>Note that system properties will still be checked before respectively
	 * after this method is invoked, according to the system properties mode.
	 * @param placeholder the placeholder to resolve
	 * @param props the merged properties of this configurer
	 * @return the resolved value, of {@code null} if none
	 * @see #setSystemPropertiesMode
	 */
	@Nullable
	protected String resolvePlaceholder(String placeholder, Properties props) {
		return props.getProperty(placeholder);
	}

	/**
	 * Resolve the given key as JVM system property, and optionally also as
	 * system environment variable if no matching system property has been found.
	 * @param key the placeholder to resolve as system property key
	 * @return the system property value, or {@code null} if not found
	 * @see #setSearchSystemEnvironment
	 * @see System#getProperty(String)
	 * @see System#getenv(String)
	 */
	@Nullable
	protected String resolveSystemProperty(String key) {
		try {
			String value = System.getProperty(key);
			if (value == null && this.searchSystemEnvironment) {
				value = System.getenv(key);
			}
			return value;
		}
		catch (Throwable ex) {
			if (logger.isDebugEnabled()) {
				logger.debug("Could not access system property '" + key + "': " + ex);
			}
			return null;
		}
	}


	/**
	 * Visit each bean definition in the given bean factory and attempt to replace ${...} property
	 * placeholders with values from the given properties.
	 */
	@Override
	protected void processProperties(ConfigurableListableBeanFactory beanFactoryToProcess, Properties props)
			throws BeansException {
		/**
		 * 利用合并转换过的Properties构建一个StringValueResolver内部类
		 */
		StringValueResolver valueResolver = new PlaceholderResolvingStringValueResolver(props);
		/**
		 * 属性处理
		 * @see PlaceholderConfigurerSupport#doProcessProperties(org.springframework.beans.factory.config.ConfigurableListableBeanFactory, org.springframework.util.StringValueResolver)
		 */
		doProcessProperties(beanFactoryToProcess, valueResolver);
	}

	/**
	 * StringValueResolver为一个解析String类型value的策略接口
	 */
	private class PlaceholderResolvingStringValueResolver implements StringValueResolver {

		/**
		 * 占位符工具类，用于替换占位符，返回真正的值
		 */
		private final PropertyPlaceholderHelper helper;

		/**
		 * PlaceholderResolver 是一个用于解析字符串中包含占位符的替换值的策略接口，
		 * 该接口有一个 #resolvePlaceholder(String strVa) 方法，用于返回占位符的替换值
		 */
		private final PlaceholderResolver resolver;

		public PlaceholderResolvingStringValueResolver(Properties props) {
			this.helper = new PropertyPlaceholderHelper(
					placeholderPrefix, placeholderSuffix, valueSeparator, ignoreUnresolvablePlaceholders);
			/**
			 * 使用传入的Properties构建一个PlaceholderResolver---占位符解析器
			 */
			this.resolver = new PropertyPlaceholderConfigurerResolver(props);
		}

		/**
		 * 解析给定String中的占位符，并返回真实值
		 * @param strVal the original String value (never {@code null})
		 * @return
		 * @throws BeansException
		 */
		@Override
		@Nullable
		public String resolveStringValue(String strVal) throws BeansException {
			/**
			 * 解析给定String中的占位符，并返回真实值
			 * @see PropertyPlaceholderHelper#parseStringValue(java.lang.String, org.springframework.util.PropertyPlaceholderHelper.PlaceholderResolver, java.util.Set)
			 */
			String resolved = this.helper.replacePlaceholders(strVal, this.resolver);
			if (trimValues) {
				resolved = resolved.trim();
			}
			return (resolved.equals(nullValue) ? null : resolved);
		}
	}


	private final class PropertyPlaceholderConfigurerResolver implements PlaceholderResolver {

		private final Properties props;

		private PropertyPlaceholderConfigurerResolver(Properties props) {
			this.props = props;
		}

		@Override
		@Nullable
		public String resolvePlaceholder(String placeholderName) {
			return PropertyPlaceholderConfigurer.this.resolvePlaceholder(placeholderName,
					this.props, systemPropertiesMode);
		}
	}

}
