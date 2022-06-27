'use strict';

const { assert } = require('chai');
const sinon = require('sinon');
const { createLogger, config } = require('winston');
const appInsights = require('applicationinsights');
const transport = require('../lib/winston-azure-application-insights');

afterEach('teardown appInsights', () => {
    appInsights.dispose();
});

describe('winston-azure-application-insights', () => {
    describe('class', () => {
        describe('constructor', () => {
            beforeEach(() => {
                delete process.env.APPINSIGHTS_INSTRUMENTATIONKEY;
            });

            it('should fail if no instrumentation insights instance, client or key specified', () => {
                assert.throws(() => {
                    new transport.AzureApplicationInsightsLogger(); // eslint-disable-line no-new
                }, /key not found/);
            });

            it('should accept an App Insights instance with the insights option', () => {
                let aiLogger;

                assert.doesNotThrow(() => {
                    appInsights.setup('FAKEKEY');

                    aiLogger = new transport.AzureApplicationInsightsLogger({
                        insights: appInsights,
                    });
                });

                assert.ok(aiLogger.client);
            });

            it('should accept an App Insights client with the client option', () => {
                let aiLogger;

                assert.doesNotThrow(() => {
                    aiLogger = new transport.AzureApplicationInsightsLogger({
                        client: new appInsights.TelemetryClient('FAKEKEY'),
                    });
                });

                assert.ok(aiLogger.client);
            });

            it('should accept an instrumentation key with the key option', () => {
                let aiLogger;

                assert.doesNotThrow(() => {
                    aiLogger = new transport.AzureApplicationInsightsLogger({
                        key: 'FAKEKEY',
                    });
                });

                assert.ok(aiLogger.client);
            });

            it('should use the APPINSIGHTS_INSTRUMENTATIONKEY environment variable if defined', () => {
                let aiLogger;

                process.env.APPINSIGHTS_INSTRUMENTATIONKEY = 'FAKEKEY';

                assert.doesNotThrow(() => {
                    aiLogger = new transport.AzureApplicationInsightsLogger();
                });

                assert.ok(aiLogger.client);
            });

            it('should set default logging level to info', () => {
                const aiLogger = new transport.AzureApplicationInsightsLogger({
                    key: 'FAKEKEY',
                });

                assert.equal(aiLogger.level, 'info');
            });

            it('should set logging level', () => {
                const aiLogger = new transport.AzureApplicationInsightsLogger({
                    key: 'FAKEKEY',
                    level: 'warn',
                });

                assert.equal(aiLogger.level, 'warn');
            });

            it('should declare a Winston logger', () => {
                const theTransport = new transport.AzureApplicationInsightsLogger({
                    key: 'FAKEKEY',
                });

                assert.ok(theTransport);
            });
        });

        describe('#log', () => {
            let logger;
            let aiTransport;
            let clientMock;

            beforeEach(() => {
                aiTransport = new transport.AzureApplicationInsightsLogger({ key: 'FAKEKEY' });
                logger = createLogger({
                    levels: config.syslog.levels,
                    transports: [aiTransport],
                });
                clientMock = sinon.mock(appInsights.defaultClient);
            });

            afterEach(() => {
                clientMock.restore();
            });

            it('should log with correct log levels', () => {
                clientMock.expects('trackTrace').once().withArgs({ message: 'error', severity: 3, properties: {} });
                clientMock.expects('trackTrace').once().withArgs({ message: 'warn', severity: 2, properties: {} });
                clientMock.expects('trackTrace').once().withArgs({ message: 'notice', severity: 1, properties: {} });
                clientMock.expects('trackTrace').once().withArgs({ message: 'info', severity: 1, properties: {} });
                clientMock.expects('trackTrace').once().withArgs({ message: 'verbose', severity: 0, properties: {} });
                clientMock.expects('trackTrace').once().withArgs({ message: 'debug', severity: 0, properties: {} });
                clientMock.expects('trackTrace').once().withArgs({ message: 'silly', severity: 0, properties: {} });

                ['error', 'warn', 'info', 'verbose', 'debug', 'silly']
                    .forEach((level) => logger.log(level, level));
            });

            it('should handle null/undefined messages', () => {
                clientMock.expects('trackTrace').once().withArgs({ message: 'null', severity: 0, properties: {} });
                clientMock.expects('trackTrace').once().withArgs({ message: 'undefined', severity: 0, properties: {} });

                [null, undefined]
                    .forEach((message) => logger.log('debug', message));
            });

            it('should call toString of message if an object', () => {
                class CustomObject {
                    constructor(value) {
                        this.value = value;
                    }

                    toString() {
                        return 'Custom toString - ' + this.value;
                    }
                }

                const customObj = new CustomObject('value');
                const date = new Date(2021, 1, 1);


                clientMock.expects('trackTrace').once().withArgs({ message: customObj.toString(), severity: 0, properties: {} });
                clientMock.expects('trackTrace').once().withArgs({ message: date.toString(), severity: 0, properties: {} });

                [customObj, date]
                    .forEach((message) => logger.log('debug', message));
            });

            it('should trace with a single param', () => {
                const msg = 'Trace msg';

                const props = {
                    propBag: true,
                };

                const testLogger = logger.child(props);

                clientMock.expects('trackTrace').once().withArgs({
                    message: msg,
                    severity: 1,
                    properties: props,
                });

                testLogger.info(msg);

                clientMock.verify();
            });

            it('should trace with supplied property bag', () => {
                const msg = 'Trace msg';

                const props = {
                    propBag: true,
                };

                const extraProps = {
                    foo: 'bar',
                };

                const testLogger = logger.child(props);

                clientMock.expects('trackTrace').once().withArgs({
                    message: msg,
                    severity: 1,
                    properties: {
                        propBag: true,
                        foo: 'bar',
                    },
                });

                testLogger.info(msg, extraProps);

                clientMock.verify();
            });

            it('should trace with log object', () => {
                const msg = 'Trace msg';

                const props = {
                    propBag: true,
                };

                const testLogger = logger.child(props);

                clientMock.expects('trackTrace').once().withArgs({
                    message: msg,
                    severity: 1,
                    properties: {
                        propBag: true,
                        foo: 'bar',
                    },
                });

                testLogger.log({
                    level: 'info',
                    message: msg,
                    foo: 'bar',
                });

                clientMock.verify();
            });
        });

        describe('#log errors as exceptions', () => {
            let logger;
            let aiTransport;
            let clientMock;

            beforeEach(() => {
                aiTransport = new transport.AzureApplicationInsightsLogger({
                    key: 'FAKEKEY',
                    sendErrorsAsExceptions: true,
                });
                logger = createLogger({
                    levels: config.syslog.levels,
                    transports: [aiTransport],
                });
                clientMock = sinon.mock(aiTransport.client);
            });

            afterEach(() => {
                clientMock.restore();
            });

            it('should not track exceptions if the option is off', () => {
                aiTransport.sendErrorsAsExceptions = false;
                clientMock.expects('trackException').never();
                logger.error(new Error('error message'));
            });

            it('should not track exceptions if level < error', () => {
                clientMock.expects('trackException').never();

                ['warning', 'notice', 'info', 'debug']
                    .forEach((level) => logger.log({ level, message: level }));
                clientMock.verify();
            });

            it('should not track exceptions if level >= error and msg is a string', () => {
                ['emerg', 'alert', 'crit', 'error']
                    .forEach((level) => {
                        const exceptionMock = clientMock.expects('trackException').never();
                        logger.log({ level, message: 'log level custom error msg' });
                        exceptionMock.verify();
                    });
                clientMock.verify();
            });

            it('should track exceptions if level == error and msg is an Error obj', () => {
                const error = new Error('error msg');

                const props = {
                    propBag: true,
                };

                const testLogger = logger.child(props);

                clientMock.expects('trackException').once().withArgs({
                    exception: sinon.match.instanceOf(Error).and(sinon.match.has('message', error.message)).and(sinon.match.has('stack', error.stack)),
                    properties: props,
                });

                clientMock.expects('trackTrace').once().withArgs({
                    message: error.message,
                    severity: 3,
                    properties: {
                        propBag: true,
                        stack: error.stack,
                    },
                });

                testLogger.error(error);

                clientMock.verify();
            });

            it('should track exceptions if level == error and meta is an Error obj', () => {
                const logMessage = 'Log handling message';
                const error = new Error('Error message');

                const props = {
                    propBag: true,
                };

                const testLogger = logger.child(props);

                clientMock.expects('trackException').once().withArgs({
                    exception: sinon.match.instanceOf(Error).and(sinon.match.has('message', `${logMessage} ${error.message}`)).and(sinon.match.has('stack', error.stack)),
                    properties: props,
                });

                clientMock.expects('trackTrace').once().withArgs({
                    message: `${logMessage} ${error.message}`,
                    severity: 3,
                    properties: {
                        propBag: true,
                        stack: error.stack
                    },
                });


                testLogger.error(logMessage, error);
                clientMock.verify();
            });

            it('should track exceptions if level == error, msg is Error and logMeta is context obj', () => {
                const logContext = {
                    propBag: true,
                };

                const extraProps = {
                    foo: 'bar',
                };

                const error = new Error('Error message');

                const testLogger = logger.child(extraProps);

                clientMock.expects('trackException').once().withArgs({
                    exception: sinon.match.instanceOf(Error).and(sinon.match.has('message', error.message)).and(sinon.match.has('stack', error.stack)),
                    properties: {
                        propBag: true,
                        foo: 'bar',
                    },
                });

                clientMock.expects('trackTrace').once().withArgs({
                    message: String(error),
                    severity: 3,
                    properties: {
                        propBag: true,
                        foo: 'bar',
                    },
                });

                testLogger.error(error, logContext);

                clientMock.verify();
            });
        });
    });

    describe('exports', () => {
        it('exposes getMessageLevel', () => {
            assert.isFunction(transport.getMessageLevel);
        });
    });
});
