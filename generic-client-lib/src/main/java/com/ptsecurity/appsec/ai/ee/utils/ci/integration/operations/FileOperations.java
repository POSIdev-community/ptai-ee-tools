package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import lombok.NonNull;

import java.io.File;

/**
 * As AST job may be executed in different environments, i.e. as part of
 * CI plugin or as a desktop application, there's need for different
 * implementations for some functions like file operations. This
 * interface defines set of methods that are used inside misc jobs and
 * are to be implemented differently
 */
public interface FileOperations {

    /** Method saves @data from file to artifact named @name. Method marked as
     * abstract as different descendants may use different approaches. For example,
     * Jenkins plugin needs to use MasterToSlaveCallable approach as workspace
     * may be located on a remote build agent
     * @param name File name to be saved
     * @param data Artifact data to save
     */
    void saveArtifact(@NonNull final String name, @NonNull final File data);

    /** Method saves @data buffer to artifact named @name. Method marked as
     * abstract as different descendants may use different approaches. For example,
     * Jenkins plugin needs to use MasterToSlaveCallable approach as workspace
     * may be located on a remote build agent
     * @param name File name to be saved
     * @param data Artifact data to save
     */
    void saveArtifact(@NonNull final String name, final byte[] data);

    /** Method saves @data buffer to artifact named @name. Method marked as
     * abstract as different descendants may use different approaches. For example,
     * Jenkins plugin needs to use MasterToSlaveCallable approach as workspace
     * may be located on a remote build agent
     * @param name File name to be saved
     * @param data Artifact data to save
     */
    void saveArtifact(@NonNull final String name, @NonNull final String data);

    /** Method saves a file that aictl has created on a host where it runs. Jenkins
     * executes aictl on a build agent while a build step itself runs in a controller
     * JVM, so an implementation is expected to move such a file within an agent
     * instead of pulling its contents through a controller and pushing them back
     * @param name File name to be saved
     * @param path Absolute path of a file on a host that runs aictl
     */
    void saveArtifactFromScanHost(@NonNull final String name, @NonNull final String path);
}
