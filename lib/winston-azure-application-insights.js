'use strict';

const appInsights = require('applicationinsights');
const Transport = require('winston-transport');

const WINSTON_LOGGER_NAME = 'applicationinsightslogger';
const WINSTON_DEFAULT_LEVEL = 'info';

// Remapping the popular levels to Application Insights
function getMessageLevel(winstonLevel) {
    const levels = {
        emerg: appInsights.Contracts.SeverityLevel.Critical,
        alert: appInsights.Contracts.SeverityLevel.Critical,
        crit: appInsights.Contracts.SeverityLevel.Critical,
        error: appInsights.Contracts.SeverityLevel.Error,
        warning: appInsights.Contracts.SeverityLevel.Warning,
        warn: appInsights.Contracts.SeverityLevel.Warning,
        notice: appInsights.Contracts.SeverityLevel.Information,
        info: appInsights.Contracts.SeverityLevel.Information,
        verbose: appInsights.Contracts.SeverityLevel.Verbose,
        debug: appInsights.Contracts.SeverityLevel.Verbose,
        silly: appInsights.Contracts.SeverityLevel.Verbose,
    };

    return winstonLevel in levels ? levels[winstonLevel] : levels.info;
}

exports.getMessageLevel = getMessageLevel;

function isErrorLike(obj) {
    return obj instanceof Error || (obj.stack && obj.message);
}

function toException(errorLike) {
    if (errorLike instanceof Error) {
        return errorLike;
    }
    const e = new Error();
    e.message = errorLike.message;
    e.stack = errorLike.stack;
    return e;
}


/**
 * Account for Winston 3.x log formatters adding properties to the log info object.
 * This just takes all properties (excluding Symbols, level, message) and returns a starter object
 * for trace properties, which make it into customDimensions.
 * @param info
 * @returns {{}}
 */
function extractPropsFromInfo(info, additionalExcludes = []) {
    const exclude = ['level', 'message'].concat(...additionalExcludes);
    return Object.keys(info)
        .filter((key) => !exclude.includes(key))
        .reduce((props, key) => Object.assign(props, { [key]: info[key] }), {});
}

class AzureApplicationInsightsLogger extends Transport {
    constructor(userOptions = {}) {
        const options = Object.assign({
            sendErrorsAsExceptions: true,
        }, userOptions);

        super(options);

        if (options.client) {
            // If client is set, just use it.
            // We expect it to be already configured and started
            this.client = options.client;
        } else if (options.insights) {
            // If insights is set, just use the default client
            // We expect it to be already configured and started
            this.client = options.insights.defaultClient;
        } else {
            // Setup insights and start it
            // If options.key is defined, use it. Else the SDK will expect
            // an environment variable to be set.

            appInsights
                .setup(options.key)
                .start();

            this.client = appInsights.defaultClient;
        }

        if (!this.client) {
            throw new Error('Could not get an Application Insights client instance');
        }

        this.name = WINSTON_LOGGER_NAME;
        this.level = options.level || WINSTON_DEFAULT_LEVEL;
        this.sendErrorsAsExceptions = !!options.sendErrorsAsExceptions;
    }

    handleTrace(severity, info, message) {
        const traceProps = extractPropsFromInfo(info);

        this.client.trackTrace({
            message: String(message),
            severity: severity,
            properties: traceProps,
        });
    }

    /**
     * Send trackException if info, message or logMeta is an Error. Otherwise, return early.
     * @param info
     * @param message
     * @param logMeta
     */
    handleException(info, message, logMeta) {
        const exceptionProps = extractPropsFromInfo(info, ['stack']);

        let error;
        if (isErrorLike(info)) {
            error = info;
        } else if (isErrorLike(message)) {
            error = message;
        } else if (isErrorLike(logMeta)) {
            error = logMeta;
        } else {
            return;
        }

        const exception = toException(error);

        this.client.trackException({
            exception,
            properties: exceptionProps,
        });
    }

    log(info, callback) {
        const { level, message } = info;
        const severity = getMessageLevel(level);
        const splat = info[Symbol.for('splat')] || [];
        const logMeta = splat.length ? splat[0] : {};

        this.handleTrace(severity, info, message);

        if (this.sendErrorsAsExceptions && severity >= getMessageLevel('error')) {
            this.handleException(info, message, logMeta);
        }

        return callback(null, true);
    }
}

exports.AzureApplicationInsightsLogger = AzureApplicationInsightsLogger;
