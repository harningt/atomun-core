package us.eharning.atomun.core.annotations

/**
 * Signifies that a public API (public class, method or field) is subject to incompatible changes,
 * or even removal, in a future release. An API bearing this annotation is exempt from any
 * compatibility guarantees made by its containing library. Note that the presence of this
 * annotation implies nothing about the quality or performance of the API in question, only the fact
 * that it is not "API-frozen."
 *
 * It is generally safe for *applications* to depend on beta APIs, at the cost of some extra
 * work during upgrades. However it is generally inadvisable for *libraries* (which get
 * included on users' CLASSPATHs, outside the library developers' control) to do so.
 */
@kotlin.annotation.Retention(AnnotationRetention.BINARY)
@kotlin.annotation.Target(
        AnnotationTarget.ANNOTATION_CLASS,
        AnnotationTarget.CONSTRUCTOR,
        AnnotationTarget.FIELD,
        AnnotationTarget.FUNCTION,
        AnnotationTarget.PROPERTY_GETTER,
        AnnotationTarget.PROPERTY_SETTER,
        AnnotationTarget.CLASS,
        AnnotationTarget.FILE
)
@MustBeDocumented
annotation class Beta